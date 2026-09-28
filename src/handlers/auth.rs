//! Anonymous account registration, sign-in, and the board-page access gate.
//!
//! Registration deliberately collects no identifying detail: a display name,
//! a unique username, a password, and an optional avatar. There is no field
//! for a real name, an address, a phone number, or an email, and none is
//! inferred from the request.
//!
//! Flow:
//!   1. `GET  /register`  renders the three-step wizard
//!   2. `POST /register`  validates every field server-side and signs the
//!      account in immediately, so the visitor never has to type the same
//!      password twice
//!   3. `GET  /login`     renders the single-screen sign-in form
//!   4. `POST /login`     verifies the Argon2id hash and issues a session
//!   5. `POST /logout`    ends the session
//!   6. `GET  /auth/username` answers whether a username is still free
//!
//! The sign-in screen also accepts a command-line administrator, which has no
//! `users` row. That identity gets an administrator session, uses the site
//! like any other member, and reaches the panel from the account menu.
//!
//! The `require_user_account` gate runs ahead of every board page and
//! redirects visitors without a session to `/login`.

use crate::{
    config::CONFIG,
    db,
    error::{AppError, Result},
    middleware::AppState,
    templates,
    templates::auth::{RegisterDraft, DISPLAY_NAME_FIELD_LABEL, USERNAME_FIELD_LABEL},
    utils::{
        crypto::{
            hash_password, make_scoped_csrf_form_token, new_csrf_token, new_session_id,
            verify_password,
        },
        redirect::strict_safe_internal_path_or,
    },
};
use anyhow::Context as _;
use axum::{
    extract::{Form, Multipart, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse as _, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::Utc;
use serde::Deserialize;
use std::sync::LazyLock;
use time::Duration;

/// Cookie carrying the opaque anonymous-account session identifier.
pub(crate) const USER_SESSION_COOKIE: &str = "chan_user_session";
/// Cookie carrying the raw CSRF token used by the sign-in and registration
/// forms. Deliberately separate from the administrator `csrf_token` cookie so
/// the two flows can never invalidate each other's forms.
const USER_CSRF_COOKIE: &str = "user_csrf_token";
/// CSRF scope for the sign-in and sign-out forms.
const LOGIN_CSRF_SCOPE: &str = "user-login";
/// CSRF scope for the registration form.
const REGISTER_CSRF_SCOPE: &str = "user-register";
/// `SameSite` policy for the account session cookie.
const USER_COOKIE_SAME_SITE: SameSite = SameSite::Lax;

/// Longest accepted display name, in characters.
const DISPLAY_NAME_MAX_CHARS: usize = 40;
/// Longest accepted username, in characters.
const USERNAME_MAX_CHARS: usize = 20;
/// Longest accepted profile description, in characters.
const BIO_MAX_CHARS: usize = 280;
/// Shortest accepted password, in characters.
const PASSWORD_MIN_CHARS: usize = 6;
/// Longest accepted password, in characters.
const PASSWORD_MAX_CHARS: usize = 256;
/// Largest accepted avatar upload, in bytes.
const AVATAR_MAX_BYTES: usize = 2 * 1024 * 1024;
/// Edge length avatars are decoded and stored at, in pixels.
const AVATAR_EDGE: u32 = 128;
/// Image formats accepted for an avatar.
const AVATAR_MIME_TYPES: [&str; 6] = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/tiff",
];

/// A registered account as the request handlers need it.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedUser {
    /// Unique login name.
    pub username: String,
    /// Name shown on posts.
    pub display_name: String,
}

impl From<crate::models::User> for AuthenticatedUser {
    fn from(user: crate::models::User) -> Self {
        Self {
            username: user.username,
            display_name: user.display_name,
        }
    }
}

/// Cookie carrying the administrator session created from the sign-in screen.
const ADMIN_SESSION_COOKIE: &str = crate::handlers::board::ADMIN_SESSION_COOKIE;

/// Build the administrator session cookie issued by the sign-in screen.
fn admin_session_cookie(session_id: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(ADMIN_SESSION_COOKIE, session_id);
    cookie.set_http_only(true);
    cookie.set_same_site(USER_COOKIE_SAME_SITE);
    cookie.set_path("/");
    cookie.set_secure(secure);
    cookie.set_max_age(Duration::seconds(CONFIG.session_duration));
    cookie
}

/// Sign a visitor in with an administrator account.
///
/// Administrators created from the command line are not anonymous board
/// accounts, so they have no `users` row. Accepting them here means one
/// sign-in screen serves both, and the existing administration session cookie
/// and panel are reused unchanged. They land on the page they came from, so an
/// operator can use the site like a member and open the panel from the account
/// menu whenever they want it.
async fn issue_admin_session(
    state: AppState,
    jar: CookieJar,
    username: &str,
    password: &str,
    secure: bool,
    return_to: &str,
) -> Result<Option<Response>> {
    let pool = state.db.clone();
    let username = username.to_owned();
    let password = password.to_owned();
    let verified = tokio::task::spawn_blocking(move || -> Result<Option<i64>> {
        let conn = pool.get()?;
        let Some(admin) = db::get_admin_by_username(&conn, &username)? else {
            return Ok(None);
        };
        if verify_password(&password, &admin.password_hash)? {
            Ok(Some(admin.id))
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    let Some(admin_id) = verified else {
        return Ok(None);
    };

    let session_id = new_session_id();
    let expires_at = Utc::now().timestamp() + CONFIG.session_duration;
    let sid = session_id.clone();
    tokio::task::spawn_blocking({
        let pool = state.db.clone();
        move || -> Result<()> {
            let conn = pool.get()?;
            db::create_session(&conn, &sid, admin_id, expires_at)?;
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    let jar = jar.add(admin_session_cookie(session_id, secure));
    tracing::info!(target: "auth", admin_id, "Administrator signed in from the sign-in screen");
    Ok(Some((jar, Redirect::to(return_to)).into_response()))
}

/// Fields submitted by the sign-in form.
#[derive(Debug, Deserialize)]
pub(crate) struct LoginForm {
    /// Entered username.
    pub username: String,
    /// Entered plaintext password.
    pub password: String,
    /// Scoped CSRF token.
    #[serde(rename = "_csrf")]
    pub csrf: Option<String>,
    /// Page to return to after signing in.
    #[serde(default)]
    pub return_to: String,
}

/// Query parameters accepted by the sign-in screen.
///
/// The screen itself never needs a password, so the field is optional here
/// and a bare `GET /login` still renders.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct LoginQuery {
    /// Username to pre-fill.
    #[serde(default)]
    username: String,
    /// Page to return to after signing in.
    #[serde(default)]
    return_to: String,
}

/// Username availability query.
#[derive(Debug, Deserialize)]
pub(crate) struct UsernameQuery {
    /// Username to test.
    username: String,
}

/// CSRF-only form body shared by the sign-out control.
#[derive(Debug, Deserialize)]
pub(crate) struct CsrfOnlyForm {
    /// Scoped CSRF token.
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Validate a submitted CSRF token against the account CSRF cookie.
fn validate_form_csrf(jar: &CookieJar, scope: &str, form_token: Option<&str>) -> bool {
    let cookie_token = jar.get(USER_CSRF_COOKIE).map(Cookie::value);
    crate::middleware::validate_signed_csrf(cookie_token, Some(scope), form_token.unwrap_or(""))
}

/// Reject a cross-site form post before anything is written.
fn require_same_origin(
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    csrf_valid: bool,
) -> Result<()> {
    crate::handlers::admin::require_same_origin_or_valid_csrf(headers, peer, csrf_valid)
}

/// Build the account CSRF cookie.
fn user_csrf_cookie(raw_token: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(USER_CSRF_COOKIE, raw_token);
    // Readable from scripts so the wizard can inspect it while it validates a
    // username, exactly as the admin panel does.
    cookie.set_http_only(false);
    cookie.set_same_site(USER_COOKIE_SAME_SITE);
    cookie.set_path("/");
    cookie.set_secure(secure);
    cookie
}

/// Return the sign-in-scoped CSRF token for the account menu's sign-out form.
///
/// The account menu lives inside the shared layout, which only has the site's
/// public token, so the form field is issued here and paired with its own
/// cookie. Validation on `POST /logout` requires that cookie to be present.
pub(crate) fn account_menu_csrf(jar: CookieJar, secure: bool) -> (CookieJar, String) {
    ensure_user_csrf(jar, secure, LOGIN_CSRF_SCOPE)
}

/// Return the account CSRF token for a page, issuing a cookie when absent.
fn ensure_user_csrf(jar: CookieJar, secure: bool, scope: &str) -> (CookieJar, String) {
    let mut jar = jar;
    let raw = match jar.get(USER_CSRF_COOKIE).map(Cookie::value) {
        Some(value) if !value.is_empty() => value.to_owned(),
        _ => {
            let raw = new_csrf_token();
            jar = jar.add(user_csrf_cookie(raw.clone(), secure));
            raw
        }
    };
    let form_token = make_scoped_csrf_form_token(&raw, &CONFIG.cookie_secret, scope);
    (jar, form_token)
}

/// Build the account session cookie.
fn user_session_cookie(session_id: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(USER_SESSION_COOKIE, session_id);
    cookie.set_http_only(true);
    cookie.set_same_site(USER_COOKIE_SAME_SITE);
    cookie.set_path("/");
    cookie.set_secure(secure);
    // The browser should expire the cookie after the configured session
    // lifetime instead of persisting it indefinitely.
    cookie.set_max_age(Duration::seconds(CONFIG.session_duration));
    cookie
}

/// Directory holding uploaded avatars.
fn avatar_dir() -> std::path::PathBuf {
    std::path::Path::new(&CONFIG.upload_dir)
        .parent()
        .map_or_else(
            || std::path::PathBuf::from("avatars"),
            |data_dir| data_dir.join("avatars"),
        )
}

/// Reject usernames that would be ambiguous or unreadable on a board.
///
/// The rule is deliberately narrow: letters, digits, `_`, `-`, and `.`, which
/// keeps a username safe to place in a URL and easy to read back.
fn username_is_well_formed(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= USERNAME_MAX_CHARS
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Normalize a username for storage and comparison.
fn normalize_username(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// Resolve the current account from the request's session cookie.
pub(crate) fn current_user(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<AuthenticatedUser>> {
    let Some(session_id) = jar.get(USER_SESSION_COOKIE).map(Cookie::value) else {
        return Ok(None);
    };
    let conn = state.db.get()?;
    let Some(session) = db::get_user_session(&conn, session_id)? else {
        return Ok(None);
    };
    Ok(db::find_user_by_id(&conn, session.user_id)?.map(AuthenticatedUser::from))
}

/// Return the id of the account carried by the request's session cookie.
///
/// Posting paths use this to attach a new post to the signed-in account so it
/// appears on that account's profile. A visitor without an account, and an
/// administrator who has no `users` row, both resolve to `None` and their posts
/// stay unlinked.
///
/// # Errors
/// Returns an error if the database query fails.
pub(crate) fn current_account_id(state: &AppState, jar: &CookieJar) -> Result<Option<i64>> {
    let Some(session_id) = jar.get(USER_SESSION_COOKIE).map(Cookie::value) else {
        return Ok(None);
    };
    let conn = state.db.get()?;
    let Some(session) = db::get_user_session(&conn, session_id)? else {
        return Ok(None);
    };
    Ok(Some(session.user_id))
}

/// Whether a request already carries a valid account session.
pub(crate) fn has_valid_session(state: &AppState, jar: &CookieJar) -> bool {
    matches!(current_user(state, jar), Ok(Some(_)))
}

/// Resolve the header account menu for a request and its sign-out token.
///
/// Every public page that shows the site header needs the same three values:
/// the menu itself, the sign-in-scoped CSRF token its sign-out form carries, and
/// the jar holding the cookie that token was issued under. Resolving them in
/// one place keeps the menu from appearing on the home page alone and going
/// missing on every board and thread.
///
/// A visitor with no session gets no menu, no token, and an untouched jar, so
/// signed-out browsing never issues an account cookie.
///
/// # Errors
/// Returns an error if the session lookup fails.
pub(crate) fn account_menu_for_request(
    state: &AppState,
    jar: CookieJar,
    secure: bool,
) -> Result<(Option<templates::auth::AccountMenu>, String, CookieJar)> {
    let Some(identity) = account_identity(state, &jar)? else {
        return Ok((None, String::new(), jar));
    };
    let (jar, token) = account_menu_csrf(jar, secure);
    Ok((
        Some(templates::auth::AccountMenu {
            display_name: identity.display_name,
            username: identity.username,
            is_admin: identity.is_admin,
        }),
        token,
        jar,
    ))
}

/// Build the `ETag` fragment that tells signed-in visitors apart.
///
/// The header account menu makes a page visitor-specific, so the `ETag` has to
/// change with the identity. Without it a browser that signs in after caching
/// the signed-out page is answered `304 Not Modified` and keeps the old body,
/// which has no account menu at all.
#[must_use]
pub(crate) fn account_etag_tag(account: Option<&templates::auth::AccountMenu>) -> String {
    account.map_or_else(String::new, |menu| {
        format!(
            "-am{}",
            crate::utils::crypto::sha256_hex(menu.username.as_bytes())
                .chars()
                .take(12)
                .collect::<String>()
        )
    })
}

/// The identity shown in the header account menu.
pub(crate) struct AccountIdentity {
    /// Name shown to other visitors.
    pub display_name: String,
    /// Unique login name.
    pub username: String,
    /// Whether this identity may also open the administration panel.
    pub is_admin: bool,
}

/// Resolve the identity carried by the administrator session cookie.
fn admin_identity(state: &AppState, jar: &CookieJar) -> Result<Option<AccountIdentity>> {
    let Some(session_id) = jar.get(ADMIN_SESSION_COOKIE).map(Cookie::value) else {
        return Ok(None);
    };
    let conn = state.db.get()?;
    let Some(session) = db::get_session(&conn, session_id)? else {
        return Ok(None);
    };
    let Some(username) = db::get_admin_name_by_id(&conn, session.admin_id)? else {
        return Ok(None);
    };
    Ok(Some(AccountIdentity {
        display_name: username.clone(),
        username,
        is_admin: true,
    }))
}

/// Resolve the signed-in identity for the account menu.
///
/// An anonymous board account wins when both cookies are present: it is the
/// identity the visitor chose on the sign-in screen, and the operator session
/// only adds the administration entry.
pub(crate) fn account_identity(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<AccountIdentity>> {
    if let Some(user) = current_user(state, jar)? {
        return Ok(Some(AccountIdentity {
            display_name: user.display_name,
            username: user.username,
            is_admin: false,
        }));
    }
    admin_identity(state, jar)
}

/// Whether a request already carries a session that may enter the site.
///
/// An operator who signed in from this screen holds an administrator session
/// instead of a `users` row, so the account gate has to accept it too. The
/// operator then browses, posts, and signs out exactly like any other member
/// and reaches the panel from the account menu.
fn has_valid_account(state: &AppState, jar: &CookieJar) -> bool {
    if has_valid_session(state, jar) {
        return true;
    }
    matches!(admin_identity(state, jar), Ok(Some(_)))
}

/// A real Argon2id hash that matches no account.
///
/// Signing in with an unknown name still performs the full password
/// verification, so the response time does not reveal whether the account
/// exists. The hash is built once on first use and kept for the process life.
static DUMMY_PASSWORD_HASH: LazyLock<String> = LazyLock::new(|| {
    hash_password(&new_session_id()).unwrap_or_else(|_| String::from(
        "$argon2id$v=19$m=65536,t=2,p=2$c29tZXNhbHR2YWx1ZQ$Jx8Yq1s0Kk5m2Yg7Qe3vJ0nP9rT4wX6bA1cD8fG0hIkL5oM2pQ7rS3tU9vW4xY6z",
    ))
});

// GET /login
pub(crate) async fn login_page(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    Query(query): Query<LoginQuery>,
) -> Result<Response> {
    // A signed-in visitor has no reason to see the sign-in screen.
    if has_valid_account(&state, &jar) {
        return Ok(Redirect::to("/").into_response());
    }

    let secure = crate::handlers::admin::should_set_secure_cookie(&headers, secure_context);
    let (jar, csrf) = ensure_user_csrf(jar, secure, LOGIN_CSRF_SCOPE);
    let html = templates::auth::login_page(
        &query.username,
        &csrf,
        None,
        strict_safe_internal_path_or(Some(&query.return_to), "/"),
    );
    Ok((jar, Html(html)).into_response())
}

// POST /login
pub(crate) async fn login_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    Form(form): Form<LoginForm>,
) -> Result<Response> {
    let secure = crate::handlers::admin::should_set_secure_cookie(&headers, secure_context);
    let csrf_valid = validate_form_csrf(&jar, LOGIN_CSRF_SCOPE, form.csrf.as_deref());
    require_same_origin(&headers, secure_context.peer, csrf_valid)?;
    if !csrf_valid {
        return Err(AppError::Forbidden("CSRF token mismatch.".into()));
    }

    let username = normalize_username(&form.username);
    // Administrator names are stored as typed, so the operator lookup uses the
    // trimmed form rather than the lower-cased board-account one.
    let operator_username = form.username.trim().to_owned();
    let return_to = strict_safe_internal_path_or(Some(&form.return_to), "/").to_owned();
    let pool = state.db.clone();
    let password = form.password.clone();

    // Argon2 is deliberately expensive, so it never runs on the async runtime.
    let verified = tokio::task::spawn_blocking(move || -> Result<Option<i64>> {
        let conn = pool.get()?;
        let Some(user) = db::find_user_by_username(&conn, &username)? else {
            // Spend the same work on an unknown name as on a known one so the
            // response time does not reveal whether the account exists.
            let _timing_equalizer = verify_password(&password, &DUMMY_PASSWORD_HASH);
            return Ok(None);
        };
        if verify_password(&password, &user.password_hash)? {
            Ok(Some(user.id))
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    let Some(user_id) = verified else {
        // Administrators created from the command line are not anonymous board
        // accounts, so fall back to the operator identity before failing.
        if let Some(response) = issue_admin_session(
            state.clone(),
            jar.clone(),
            &operator_username,
            &form.password,
            secure,
            &return_to,
        )
        .await?
        {
            return Ok(response);
        }
        return Ok(render_login_failure(
            jar,
            secure,
            &form.username,
            "Kullanıcı adı veya parola hatalı.",
        ));
    };

    issue_session(state, jar, user_id, secure, &return_to).await
}

/// Render the sign-in screen again with a failure message.
fn render_login_failure(
    jar: CookieJar,
    secure: bool,
    username: &str,
    message: &str,
) -> Response {
    let (jar, csrf) = ensure_user_csrf(jar, secure, LOGIN_CSRF_SCOPE);
    let html = templates::auth::login_page(username, &csrf, Some(message), "/");
    (jar, Html(html)).into_response()
}

/// Create the session row and hand back the redirect that enters the site.
async fn issue_session(
    state: AppState,
    jar: CookieJar,
    user_id: i64,
    secure: bool,
    return_to: &str,
) -> Result<Response> {
    let session_id = new_session_id();
    let expires_at = Utc::now().timestamp() + CONFIG.session_duration;
    let sid = session_id.clone();
    tokio::task::spawn_blocking({
        let pool = state.db.clone();
        move || -> Result<()> {
            let conn = pool.get()?;
            db::create_user_session(&conn, &sid, user_id, expires_at)?;
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    let jar = jar.add(user_session_cookie(session_id, secure));
    tracing::info!(target: "auth", user_id, "Anonymous account signed in");
    Ok((jar, Redirect::to(return_to)).into_response())
}

// POST /logout
pub(crate) async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    Form(form): Form<CsrfOnlyForm>,
) -> Result<Response> {
    let csrf_valid = validate_form_csrf(&jar, LOGIN_CSRF_SCOPE, form.csrf.as_deref());
    require_same_origin(&headers, secure_context.peer, csrf_valid)?;
    if !csrf_valid {
        return Err(AppError::Forbidden("CSRF token mismatch.".into()));
    }

    if let Some(session) = jar.get(USER_SESSION_COOKIE) {
        let session_id = session.value().to_owned();
        let pool = state.db.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = pool.get()?;
            db::delete_user_session(&conn, &session_id)?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;
    }

    // An administrator who signed in from this screen holds an operator
    // session as well, so signing out has to end that one too.
    let admin_session_id = jar
        .get(ADMIN_SESSION_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    if let Some(session_id) = admin_session_id {
        let pool = state.db.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = pool.get()?;
            db::delete_session(&conn, &session_id)?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;
    }

    let jar = jar
        .remove(Cookie::from(USER_SESSION_COOKIE))
        .remove(Cookie::from(USER_CSRF_COOKIE))
        .remove(Cookie::from(ADMIN_SESSION_COOKIE));
    Ok((jar, Redirect::to("/login")).into_response())
}

// GET /register
pub(crate) async fn register_page(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
) -> Result<Response> {
    if has_valid_session(&state, &jar) {
        return Ok(Redirect::to("/").into_response());
    }

    let secure = crate::handlers::admin::should_set_secure_cookie(&headers, secure_context);
    let (jar, csrf) = ensure_user_csrf(jar, secure, REGISTER_CSRF_SCOPE);
    let html = templates::auth::register_page(&csrf, 1, &RegisterDraft::default(), None);
    Ok((jar, Html(html)).into_response())
}

// POST /register
#[expect(
    clippy::too_many_lines,
    reason = "each field is validated with its own user-facing message before anything is written"
)]
pub(crate) async fn register_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    multipart: Multipart,
) -> Result<Response> {
    let secure = crate::handlers::admin::should_set_secure_cookie(&headers, secure_context);

    let submitted = read_register_multipart(multipart).await?;
    let csrf_valid = validate_form_csrf(&jar, REGISTER_CSRF_SCOPE, submitted.csrf.as_deref());
    require_same_origin(&headers, secure_context.peer, csrf_valid)?;
    if !csrf_valid {
        return Err(AppError::Forbidden("CSRF token mismatch.".into()));
    }

    let draft = RegisterDraft {
        display_name: submitted.display_name.clone(),
        username: submitted.username.clone(),
        bio: submitted.bio.clone(),
        username_available: None,
    };
    let step = submitted.step.unwrap_or(1).clamp(1, 3);

    // Validate everything before touching the database or the filesystem so a
    // rejected registration leaves nothing behind.
    let display_name = submitted.display_name.trim();
    if display_name.is_empty() {
        return Ok(render_register_failure(
            jar,
            secure,
            step,
            &draft,
            &format!("{DISPLAY_NAME_FIELD_LABEL} boş bırakılamaz."),
        ));
    }
    if display_name.chars().count() > DISPLAY_NAME_MAX_CHARS {
        return Ok(render_register_failure(
            jar,
            secure,
            step,
            &draft,
            &format!(
                "{DISPLAY_NAME_FIELD_LABEL} en fazla {DISPLAY_NAME_MAX_CHARS} karakter olabilir."
            ),
        ));
    }

    let username = normalize_username(&submitted.username);
    if !username_is_well_formed(&username) {
        return Ok(render_register_failure(
            jar,
            secure,
            step,
            &draft,
            &format!(
                "{USERNAME_FIELD_LABEL} yalnızca harf, rakam, `_`, `-` ve `.` içerebilir; en fazla {USERNAME_MAX_CHARS} karakter."
            ),
        ));
    }

    if submitted.password.chars().count() < PASSWORD_MIN_CHARS {
        return Ok(render_register_failure(
            jar,
            secure,
            3,
            &draft,
            &format!("Parola en az {PASSWORD_MIN_CHARS} karakter olmalı."),
        ));
    }
    if submitted.password.chars().count() > PASSWORD_MAX_CHARS {
        return Ok(render_register_failure(
            jar,
            secure,
            3,
            &draft,
            "Parola çok uzun.",
        ));
    }
    if submitted.password != submitted.password_confirm {
        return Ok(render_register_failure(
            jar,
            secure,
            3,
            &draft,
            "Parolalar eşleşmiyor.",
        ));
    }

    // The description is optional, but a very long one is a rejected form
    // rather than a silently truncated profile.
    let bio = submitted.bio.trim();
    if bio.chars().count() > BIO_MAX_CHARS {
        return Ok(render_register_failure(
            jar,
            secure,
            2,
            &draft,
            &format!("Bio en fazla {BIO_MAX_CHARS} karakter olabilir."),
        ));
    }
    let bio = bio.to_owned();

    // The avatar is optional; a file that is present must still be a real
    // image within the size bound.
    let avatar_bytes = match submitted.avatar {
        Some(bytes) if !bytes.is_empty() => {
            if bytes.len() > AVATAR_MAX_BYTES {
                return Ok(render_register_failure(
                    jar,
                    secure,
                    2,
                    &draft,
                    "Profil resmi en fazla 2 MiB olabilir.",
                ));
            }
            Some(bytes)
        }
        _ => None,
    };

    let password = submitted.password.clone();
    let pool = state.db.clone();
    let name_for_lookup = username.clone();
    let name_to_store = username.clone();
    let display_name = display_name.to_owned();

    // Insert and hash on the blocking pool: the unique index is the final
    // authority on a taken username, so a racing registration is rejected
    // rather than silently overwriting the first account.
    let created = tokio::task::spawn_blocking(move || -> Result<Option<i64>> {
        let conn = pool.get()?;
        if db::username_exists(&conn, &name_for_lookup)? {
            return Ok(None);
        }
        let password_hash = hash_password(&password)?;
        let insert = db::create_user(
            &conn,
            &name_to_store,
            &display_name,
            &password_hash,
            None,
            &bio,
        );
        let inserted = match insert {
            Ok(id) => Ok(Some(id)),
            Err(error) if is_unique_violation(&error) => {
                tracing::debug!(target: "auth", "username taken during registration");
                Ok(None)
            }
            Err(error) => Err(AppError::from(error)),
        };
        inserted
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    let Some(user_id) = created? else {
        return Ok(render_register_failure(
            jar,
            secure,
            2,
            &draft,
            "Bu kullanıcı adı zaten alınmış.",
        ));
    };

    // The avatar is written after the row exists so an unwritable directory
    // still leaves a usable account rather than a half-created one.
    if let Some(bytes) = avatar_bytes {
        match store_avatar(user_id, &bytes) {
            Ok(file_name) => {
                let pool = state.db.clone();
                tokio::task::spawn_blocking(move || -> Result<()> {
                    let conn = pool.get()?;
                    db::set_user_avatar(&conn, user_id, &file_name)?;
                    Ok(())
                })
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;
            }
            Err(error) => {
                tracing::warn!(
                    target: "auth",
                    user_id,
                    "Avatar rejected, account created with the default avatar: {error}"
                );
            }
        }
    }

    tracing::info!(target: "auth", user_id, "Anonymous account registered");

    // Registration signs the visitor straight in, so they never type the same
    // password twice. The confirmation page replaces the home page redirect.
    let session_id = new_session_id();
    let expires_at = Utc::now().timestamp() + CONFIG.session_duration;
    let sid = session_id.clone();
    tokio::task::spawn_blocking({
        let pool = state.db.clone();
        move || -> Result<()> {
            let conn = pool.get()?;
            db::create_user_session(&conn, &sid, user_id, expires_at)?;
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    let jar = jar.add(user_session_cookie(session_id, secure));
    Ok((jar, Redirect::to("/?kayit=1")).into_response())
}

/// Whether a database error is a `UNIQUE` constraint failure.
fn is_unique_violation(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<rusqlite::Error>()
            .is_some_and(|db_error| {
                db_error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation)
            })
    })
}/// Render the wizard again with a failure message.
fn render_register_failure(
    jar: CookieJar,
    secure: bool,
    step: u32,
    draft: &RegisterDraft,
    message: &str,
) -> Response {
    let (jar, csrf) = ensure_user_csrf(jar, secure, REGISTER_CSRF_SCOPE);
    let html = templates::auth::register_page(&csrf, step, draft, Some(message));
    (jar, Html(html)).into_response()
}

/// Decode and store an avatar, returning the file name to persist.
///
/// Everything is re-encoded as a square PNG so the file name always matches
/// the bytes on disk and the response content type stays correct.
fn store_avatar(user_id: i64, bytes: &[u8]) -> Result<String> {
    let decoded = image::load_from_memory(bytes).context("Failed to decode avatar image")?;
    let format = image::guess_format(bytes).context("Failed to detect avatar format")?;
    let mime_name = match format {
        image::ImageFormat::Jpeg => "image/jpeg",
        image::ImageFormat::Png => "image/png",
        image::ImageFormat::Gif => "image/gif",
        image::ImageFormat::WebP => "image/webp",
        image::ImageFormat::Bmp => "image/bmp",
        image::ImageFormat::Tiff => "image/tiff",
        _ => return Err(anyhow::anyhow!("unsupported avatar format").into()),
    };
    if !AVATAR_MIME_TYPES.contains(&mime_name) {
        return Err(anyhow::anyhow!("unsupported avatar format").into());
    }

    let resized = crate::media::exif::apply_exif_orientation(decoded, 1)
        .resize(AVATAR_EDGE, AVATAR_EDGE, image::imageops::FilterType::Lanczos3);
    let mut encoded = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(resized.to_rgba8())
        .write_to(&mut encoded, image::ImageFormat::Png)
        .context("Failed to encode avatar")?;

    let dir = avatar_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create avatar directory {}", dir.display()))?;
    let file_name = format!("{user_id}.png");
    let path = dir.join(&file_name);
    std::fs::write(&path, encoded.into_inner())
        .with_context(|| format!("Failed to write avatar {}", path.display()))?;
    Ok(file_name)
}

// GET /auth/avatar/{user_id}
pub(crate) async fn serve_avatar(
    State(state): State<AppState>,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
) -> Result<Response> {
    let file_name = format!("{user_id}.png");
    let path = avatar_dir().join(&file_name);
    // A missing file is not an error: the account simply uses the generated
    // default avatar.
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => {
            let conn = state.db.get()?;
            let Some(user) = db::find_user_by_id(&conn, user_id)? else {
                return Err(AppError::NotFound("Profil resmi bulunamadı.".into()));
            };
            default_avatar(&user.username)?
        }
    };
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("image/png"),
    );
    crate::cache::set_cache_control(headers, crate::cache::CACHE_CONTROL_IMMUTABLE_MEDIA);
    Ok(response)
}

/// Number of pixel columns in one built-in font glyph.
const GLYPH_COLUMNS: usize = 5;

/// Number of pixel rows in one built-in font glyph.
const GLYPH_ROWS: usize = 7;

/// One font pixel is drawn as a block this many image pixels on a side.
///
/// Dividing the avatar edge keeps the glyph a fixed fraction of the image, so
/// the initial stays readable and centered at any avatar size.
const GLYPH_SCALE: usize = (AVATAR_EDGE / 10) as usize;

/// Return the character an account's fallback avatar is drawn with.
///
/// Usernames are stored lower-cased and restricted to ASCII letters, digits,
/// `_`, `-`, and `.`, so the first alphanumeric character of the username is
/// the account's initial. A name with none falls back to `?`.
fn avatar_initial(username: &str) -> char {
    username
        .chars()
        .find(|c| c.is_ascii_alphanumeric())
        .map_or('?', |c| c.to_ascii_uppercase())
}

/// Return the bitmap of one character for the fallback avatar.
///
/// Each entry is one row, top to bottom, where bit 0 is the leftmost column:
/// `0x1F` is a full row and `0x11` the two vertical strokes of a letter like
/// `H`. Only the characters an account name can start with are drawn; anything
/// else uses the same `?` an account with no initial at all gets, so an
/// unsupported character can never render as a blank tile.
///
/// The font is embedded rather than pulled from a crate: an avatar needs one
/// glyph, and a font dependency would weigh more than the image it decorates.
fn glyph_rows(c: char) -> [u8; GLYPH_ROWS] {
    match c {
        'A' => [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'B' => [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E],
        'C' => [0x0F, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0F],
        'D' => [0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E],
        'E' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F],
        'F' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
        'G' => [0x0E, 0x11, 0x10, 0x13, 0x11, 0x11, 0x0E],
        'H' => [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'I' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1F],
        'J' => [0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0C],
        'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F],
        'M' => [0x11, 0x1B, 0x15, 0x11, 0x11, 0x11, 0x11],
        'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        'O' => [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'P' => [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
        'Q' => [0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D],
        'R' => [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11],
        'S' => [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
        'T' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04],
        'W' => [0x11, 0x11, 0x11, 0x11, 0x15, 0x1B, 0x11],
        'X' => [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
        'Y' => [0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04],
        'Z' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F],
        '0' => [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
        '1' => [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
        '2' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
        '3' => [0x1F, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1F],
        '4' => [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
        '5' => [0x1F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
        '6' => [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
        '7' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        '8' => [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
        '9' => [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x06],
        _ => [0x0E, 0x11, 0x01, 0x06, 0x04, 0x00, 0x04],
    }
}

/// Render the fallback avatar used when no file was uploaded.
///
/// The tile pattern and its colors are derived from the username so two
/// anonymous accounts never look identical, without storing anything extra for
/// the account. The account's initial is drawn over that pattern, so a visitor
/// who never chose a picture still sees which account they are looking at
/// instead of an empty tile.
fn default_avatar(username: &str) -> Result<Vec<u8>> {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let channel = |index: usize| -> u8 {
        u8::from_str_radix(digest.get(index * 2..index * 2 + 2).unwrap_or("00"), 16)
            .unwrap_or(0)
            % 64
    };
    let base = image::Rgb([
        48u8.saturating_add(channel(0)),
        48u8.saturating_add(channel(1)),
        48u8.saturating_add(channel(2)),
    ]);
    let accent = image::Rgb([
        base.0[0].saturating_add(40),
        base.0[1].saturating_add(40),
        base.0[2].saturating_add(40),
    ]);
    // A light tint of the tile colors, so the initial reads on both halves of
    // the pattern.
    let ink = image::Rgb([
        base.0[0].saturating_add(120),
        base.0[1].saturating_add(150),
        base.0[2].saturating_add(120),
    ]);

    // The glyph is scaled up and centered, so it reads as a letter rather than
    // as noise in the middle of the pattern.
    let edge = AVATAR_EDGE as usize;
    let scale = GLYPH_SCALE.max(1);
    let glyph_width = GLYPH_COLUMNS * scale;
    let glyph_height = GLYPH_ROWS * scale;
    let origin_x = edge.saturating_sub(glyph_width) / 2;
    let origin_y = edge.saturating_sub(glyph_height) / 2;
    let glyph = glyph_rows(avatar_initial(username));

    let tile = 16usize;
    let canvas = image::RgbImage::from_fn(AVATAR_EDGE, AVATAR_EDGE, |x, y| {
        let (x, y) = (x as usize, y as usize);
        if x >= origin_x
            && x < origin_x + glyph_width
            && y >= origin_y
            && y < origin_y + glyph_height
            && (glyph[(y - origin_y) / scale] >> ((x - origin_x) / scale)) & 1 == 1
        {
            return ink;
        }
        if ((y / tile) + (x / tile)) % 2 == 0 {
            base
        } else {
            accent
        }
    });
    let mut buffer = std::io::Cursor::new(Vec::new());
    canvas
        .write_to(&mut buffer, image::ImageFormat::Png)
        .context("Failed to encode default avatar")?;
    Ok(buffer.into_inner())
}

// GET /auth/username
pub(crate) async fn username_available(
    State(state): State<AppState>,
    Query(query): Query<UsernameQuery>,
) -> Result<Response> {
    let username = normalize_username(&query.username);
    if !username_is_well_formed(&username) {
        return Ok(availability_response(false));
    }
    let conn = state.db.get()?;
    let taken = db::username_exists(&conn, &username)?;
    Ok(availability_response(!taken))
}

/// Minimal JSON response for the availability probe.
fn availability_response(available: bool) -> Response {
    let body = if available {
        r#"{"available":true}"#
    } else {
        r#"{"available":false}"#
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// Fields collected by the registration form.
struct SubmittedRegister {
    /// Name shown on posts.
    display_name: String,
    /// Requested unique username.
    username: String,
    /// Chosen plaintext password.
    password: String,
    /// Repeated plaintext password.
    password_confirm: String,
    /// Short profile description.
    bio: String,
    /// Scoped CSRF token.
    csrf: Option<String>,
    /// One-based step the form was submitted from.
    step: Option<u32>,
    /// Optional avatar bytes.
    avatar: Option<Vec<u8>>,
}

/// Read the wizard's multipart body, bounding every field.
async fn read_register_multipart(mut multipart: Multipart) -> Result<SubmittedRegister> {
    let mut out = SubmittedRegister {
        display_name: String::new(),
        username: String::new(),
        password: String::new(),
        password_confirm: String::new(),
        bio: String::new(),
        csrf: None,
        step: None,
        avatar: None,
    };

    loop {
        // Bind the field to a local instead of using it as a `while let`
        // scrutinee: the field and the multipart error own custom destructors,
        // and a tail expression would drop them in a different order under the
        // Rust 2024 rules than under the 2021 rules this crate still uses.
        let next_field = multipart
            .next_field()
            .await
            .map_err(|error| AppError::BadRequest(format!("Form okunamadı: {error}")))?;
        let Some(field) = next_field else {
            break;
        };
        let name = field.name().unwrap_or("").to_owned();
        if field.file_name().is_some() {
            let bytes = field
                .bytes()
                .await
                .map_err(|error| AppError::BadRequest(format!("Dosya okunamadı: {error}")))?;
            if bytes.len() > AVATAR_MAX_BYTES {
                return Err(AppError::BadRequest("Profil resmi çok büyük.".into()));
            }
            out.avatar = Some(bytes.to_vec());
        } else {
            let value = field
                .text()
                .await
                .map_err(|error| AppError::BadRequest(format!("Form okunamadı: {error}")))?;
            match name.as_str() {
                "display_name" => out.display_name = value,
                "username" => out.username = value,
                "password" => out.password = value,
                "password_confirm" => out.password_confirm = value,
                "bio" => out.bio = value,
                "_csrf" => out.csrf = Some(value),
                "step" => out.step = value.parse().ok(),
                _ => {}
            }
        }
    }

    Ok(out)
}

/// Paths that stay reachable while the account gate is on.
const GATE_OPEN_PREFIXES: [&str; 19] = [
    "/healthz",
    "/readyz",
    "/metrics",
    "/static/",
    "/login",
    "/register",
    "/logout",
    "/auth/",
    "/setup",
    "/banned",
    "/nsfw",
    "/theme",
    "/theme-css/",
    "/favicon",
    "/apple-touch-icon",
    "/android-chrome",
    "/captcha/",
    "/banner/",
    "/preferences",
];

/// Whether a path is exempt from the account gate.
///
/// Everything else — the home page, boards, threads, posts, search, catalogs,
/// and board media — requires a session. The exemptions are the surfaces an
/// operator or a signed-out visitor genuinely needs: health probes, static
/// assets, the sign-in and registration screens, ban handling, theme and
/// preference cookies, and the setup wizard. The administration panel is
/// routed through its own layer and is never gated here.
fn path_is_exempt(path: &str) -> bool {
    GATE_OPEN_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Redirect anonymous visitors to the sign-in screen before any board page.
pub(crate) async fn require_user_account_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response> {
    if !state.require_user_account {
        return Ok(next.run(request).await);
    }
    if path_is_exempt(request.uri().path()) {
        return Ok(next.run(request).await);
    }
    if has_valid_account(&state, &jar) {
        return Ok(next.run(request).await);
    }

    // A redirect would drop the request body, so a submission from a
    // signed-out visitor is refused outright instead of being bounced.
    if !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) {
        return Err(AppError::Forbidden(
            "Bu işlem için önce giriş yapmalısın.".into(),
        ));
    }
    Ok(Redirect::to("/login").into_response())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{avatar_initial, default_avatar, AVATAR_EDGE};

    #[test]
    /// The generated avatar leads with the first letter of the account name.
    fn generated_avatar_uses_the_first_letter_of_the_name() {
        assert_eq!(avatar_initial("anon"), 'A');
        assert_eq!(avatar_initial("9mayak"), '9');
        assert_eq!(avatar_initial("_-.anonymous"), 'A');
        assert_eq!(avatar_initial("___"), '?');
        assert_eq!(avatar_initial(""), '?');
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the test asserts on the decoded avatar, so a failed encode must fail the test immediately"
    )]
    /// An account with no uploaded picture is drawn with its initial over the
    /// pattern, not left as a bare tile.
    fn generated_avatar_draws_the_initial_over_the_pattern() {
        let png = default_avatar("anon").expect("the fallback avatar should encode");
        let decoded = image::load_from_memory_with_format(&png, image::ImageFormat::Png)
            .expect("the fallback avatar should be a readable PNG")
            .to_rgb8();
        assert_eq!(decoded.width(), AVATAR_EDGE);
        assert_eq!(decoded.height(), AVATAR_EDGE);

        let mut counts: BTreeMap<[u8; 3], usize> = BTreeMap::new();
        for pixel in decoded.pixels() {
            *counts.entry(pixel.0).or_insert(0) += 1;
        }
        assert_eq!(
            counts.len(),
            3,
            "the tile pattern plus the initial, expected {counts:?}"
        );

        // The glyph is drawn in the middle, so the center pixel carries the
        // least frequent color: the initial over both halves of the pattern.
        let center = decoded.get_pixel(AVATAR_EDGE / 2, AVATAR_EDGE / 2).0;
        let least_frequent = counts.iter().min_by_key(|(_, count)| **count).map(|(c, _)| *c);
        assert_eq!(
            least_frequent,
            Some(center),
            "the initial should be drawn in the middle of the avatar"
        );
    }
}
