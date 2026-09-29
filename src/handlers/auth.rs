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
//!   4. `POST /login`     verifies the Argon2id hash and issues a session,
//!      after counting the attempt against the address and the name so a run
//!      of guesses is refused before any further hashing is paid for
//!   5. `POST /logout`    ends the session
//!   6. `GET  /auth/username` answers whether a username is still free
//!
//! Once signed in, the account menu in the shared header opens the settings
//! screen, which is the one place an account can change itself:
//!   7. `GET  /account/edit`    renders the picture, name, username,
//!      description, and password forms
//!   8. `POST /account/profile` stores the picture, the display name, a new
//!      unique username, and the description the profile shows
//!   9. `POST /account/password` replaces the password after the current one
//!      is verified, ends every session opened with the old one, and signs the
//!      visitor back in on a session id minted after the change
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
    models::{Board, User},
    templates,
    templates::auth::{
        AccountSettings, AccountSettingsNotice, AccountSettingsTokens, RegisterDraft,
        DISPLAY_NAME_FIELD_LABEL, USERNAME_FIELD_LABEL,
    },
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
use dashmap::DashMap;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
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
/// CSRF scope for the account settings forms.
///
/// Deliberately its own scope: the token only authorises editing the signed-in
/// account, so a form token lifted off a sign-in or registration page cannot be
/// replayed against the settings screen.
const ACCOUNT_CSRF_SCOPE: &str = "user-account";
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
    /// Account row identifier, used to serve the account's picture.
    pub user_id: i64,
    /// Stored avatar file name, when the account uploaded one.
    pub avatar_file: Option<String>,
}

impl From<User> for AuthenticatedUser {
    fn from(user: User) -> Self {
        Self {
            username: user.username,
            display_name: user.display_name,
            user_id: user.id,
            avatar_file: user.avatar_file,
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
    // The operator is signing in on the public sign-in screen, so they are
    // given both sessions. The board account is what every page outside the
    // administration panel asks for — a profile, a message thread, a
    // notification — and an operator without one was told to sign in again on a
    // page they had already signed in to.
    let user_session_id = new_session_id();
    let user_sid = user_session_id.clone();
    let operator_name = username.clone();
    tokio::task::spawn_blocking({
        let pool = state.db.clone();
        move || -> Result<i64> {
            let conn = pool.get()?;
            db::create_session(&conn, &sid, admin_id, expires_at)?;
            db::ensure_admin_profile(&conn, &operator_name)?;
            let account_name = operator_name.trim().to_lowercase();
            let user_id = db::find_user_by_username(&conn, &account_name)?
                .ok_or_else(|| anyhow::anyhow!("the administrator has no board profile"))?
                .id;
            db::create_user_session(&conn, &user_sid, user_id, expires_at)?;
            Ok(user_id)
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    let jar = jar
        .add(admin_session_cookie(session_id, secure))
        .add(user_session_cookie(user_session_id, secure));
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

/// Fields collected by the password change form.
///
/// Every password field defaults to empty so a truncated or hand-written post
/// is answered with the visitor-facing message the form shows, rather than with
/// a bare extractor rejection.
#[derive(Debug, Deserialize)]
pub(crate) struct PasswordChangeForm {
    /// Scoped CSRF token.
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    /// The password the account signs in with today.
    #[serde(default)]
    current_password: String,
    /// The chosen replacement password.
    #[serde(default)]
    password: String,
    /// The repeated replacement password.
    #[serde(default)]
    password_confirm: String,
}

/// Query parameters accepted by the account settings screen.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct AccountEditQuery {
    /// Which form reported a successful save.
    saved: Option<String>,
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

/// Return the id of the account a posting must be attached to.
///
/// Writing belongs to accounts. A post with nobody behind it cannot be voted
/// on, cannot be shared under a name, and cannot be found again on the profile
/// of whoever wrote it — so an anonymous post is refused in words at the door
/// rather than accepted and then disconnected from everything that could
/// answer for it.
///
/// A suspended account keeps its session and can still read the site, so this
/// is also the one place that turns that state into a refusal: writing is what
/// a suspension takes away.
///
/// # Errors
/// Returns an error if the visitor is not signed in, if the account is
/// suspended, or if the database query fails.
pub(crate) fn posting_account_id(state: &AppState, jar: &CookieJar) -> Result<i64> {
    let Some(user_id) = current_account_id(state, jar)? else {
        return Err(AppError::Forbidden(
            "Gönderi yapmak için giriş yapmalısın.".into(),
        ));
    };
    let conn = state.db.get()?;
    let account = db::find_user_by_id(&conn, user_id)?.ok_or_else(|| {
        AppError::Forbidden("Bu hesap artık yok.".into())
    })?;
    if !account.effective_status(Utc::now().timestamp()).may_post() {
        return Err(AppError::Forbidden(
            "Hesabın geçici olarak askıya alındığı için yazamazsın.".into(),
        ));
    }
    Ok(user_id)
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
            user_id: identity.user_id,
            avatar_file: identity.avatar_file,
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
    /// Account row identifier, when the identity has a board account.
    ///
    /// The bottom navigation draws the visitor's own picture in its last slot,
    /// and a picture is served by account row. An operator who has not been
    /// given a board profile has none and is drawn as a letter instead.
    pub user_id: Option<i64>,
    /// Stored avatar file name, when the account uploaded one.
    pub avatar_file: Option<String>,
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
        user_id: None,
        avatar_file: None,
    }))
}

/// Resolve the signed-in identity for the account menu.
///
/// An anonymous board account wins when both cookies are present: it is the
/// identity the visitor chose on the sign-in screen. The operator session
/// still adds the administration entry, so a signed-in administrator is shown
/// as the account they post as and is still offered the panel.
pub(crate) fn account_identity(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<AccountIdentity>> {
    if let Some(user) = current_user(state, jar)? {
        let is_admin = matches!(admin_identity(state, jar), Ok(Some(_)));
        return Ok(Some(AccountIdentity {
            display_name: user.display_name,
            username: user.username,
            is_admin,
            user_id: Some(user.user_id),
            avatar_file: user.avatar_file,
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

/// Failed sign-ins allowed per address inside [`LOGIN_FAIL_WINDOW`].
const LOGIN_FAIL_LIMIT: u32 = 8;
/// Failed sign-ins allowed against one account before it is locked.
///
/// Counted separately from the address, because guessing a single name is
/// worth doing from many addresses while one address signing many people in is
/// ordinary, so the two limits are deliberately not the same number.
const ACCOUNT_LOGIN_FAIL_LIMIT: u32 = 20;
/// Sliding window, in seconds, that sign-in failures are counted over.
const LOGIN_FAIL_WINDOW: u64 = 900;

/// `key` -> (`fail_count`, `window_start_secs`).
///
/// Keys are SHA-256 digests of the address and of the account name, so no raw
/// address or submitted name is retained in memory.
static LOGIN_FAILS: LazyLock<DashMap<String, (u32, u64)>> = LazyLock::new(DashMap::new);
/// Timestamp of the last opportunistic sweep over [`LOGIN_FAILS`].
static LOGIN_FAILS_PRUNED: AtomicU64 = AtomicU64::new(0);

/// Seconds since the Unix epoch, for the sign-in failure windows.
fn login_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build the in-memory key for one failure counter.
///
/// `purpose` keeps an address counter and an account counter apart, so the same
/// text cannot collide across the two.
fn login_fail_key(purpose: &str, value: &str) -> String {
    let mut material = String::with_capacity(purpose.len() + value.len() + 1);
    material.push_str(purpose);
    material.push(':');
    material.push_str(value.trim());
    crate::utils::crypto::sha256_hex(material.as_bytes())
}

/// Whether a counter has reached `limit` inside the current window.
fn login_fails_locked(key: &str, limit: u32) -> bool {
    let now = login_now_secs();
    if let Some(entry) = LOGIN_FAILS.get(key) {
        let (count, window_start) = *entry;
        if now.saturating_sub(window_start) <= LOGIN_FAIL_WINDOW {
            return count >= limit;
        }
    }
    false
}

/// Record one failure and return the new count.
///
/// The window is measured from the first failure of a run, so an attacker
/// cannot extend a lockout by keeping the counter warm.
#[expect(
    clippy::significant_drop_tightening,
    reason = "the DashMap entry guard must remain held while its attempt count is updated"
)]
fn record_login_fail(key: &str) -> u32 {
    let now = login_now_secs();
    let mut entry = LOGIN_FAILS.entry(key.to_owned()).or_insert((0, now));
    let (count, window_start) = entry.value_mut();
    if now.saturating_sub(*window_start) > LOGIN_FAIL_WINDOW {
        *count = 1;
        *window_start = now;
    } else {
        *count = count.saturating_add(1);
    }
    *count
}

/// Forget the failures recorded for a successful sign-in, so an operator who
/// fumbled their own password is not locked out by their own typos.
fn clear_login_fails(keys: &[String]) {
    for key in keys {
        LOGIN_FAILS.remove(key);
    }
}

/// Drop counters whose window has passed.
///
/// Called from the background task in `server/server.rs`; a sustained attack
/// that never signs in successfully would otherwise grow the map forever.
pub(in crate::server) fn prune_login_fails() {
    let now = login_now_secs();
    let last = LOGIN_FAILS_PRUNED.load(Ordering::Relaxed);
    if now.saturating_sub(last) < LOGIN_FAIL_WINDOW {
        return;
    }
    LOGIN_FAILS_PRUNED.store(now, Ordering::Relaxed);
    LOGIN_FAILS
        .retain(|_, (_, window_start)| now.saturating_sub(*window_start) <= LOGIN_FAIL_WINDOW);
}

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
    crate::middleware::ClientIp(client_ip): crate::middleware::ClientIp,
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
    let fail_keys = signin_fail_keys(&client_ip, &operator_username);
    // The lockout is checked before Argon2 runs, so a locked-out guess costs the
    // server nothing while a real sign-in still pays the full hash.
    if signin_locked(&fail_keys) {
        tracing::warn!(target: "auth", "Account sign-in blocked by brute-force lockout");
        return Ok(render_login_failure(
            jar,
            secure,
            &form.username,
            "Çok fazla başarısız giriş denemesi. Lütfen birkaç dakika bekleyip tekrar dene.",
        ));
    }
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
            clear_login_fails(&fail_keys);
            return Ok(response);
        }
        let fails = record_signin_failure(&fail_keys);
        tracing::warn!(target: "auth", attempts = fails, "Failed account sign-in");
        return Ok(render_login_failure(
            jar,
            secure,
            &form.username,
            "Kullanıcı adı veya parola hatalı.",
        ));
    };

    clear_login_fails(&fail_keys);
    // A ban is the account's own state, not a failed password: it is reported
    // plainly so the visitor knows an operator ended the account rather than
    // that they mistyped again.
    let banned = tokio::task::spawn_blocking({
        let pool = state.db.clone();
        move || -> Result<bool> {
            let conn = pool.get()?;
            let Some(account) = db::find_user_by_id(&conn, user_id)? else {
                return Ok(false);
            };
            Ok(!account.effective_status(Utc::now().timestamp()).may_sign_in())
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;
    if banned {
        return Ok(render_login_failure(
            jar,
            secure,
            &form.username,
            "Bu hesap banlandı.",
        ));
    }

    issue_session(state, jar, user_id, secure, &return_to).await
}

/// The two counters a sign-in attempt is measured against.
///
/// The pair is returned together because every read, write, and clear of a
/// sign-in failure touches both.
fn signin_fail_keys(client_ip: &str, username: &str) -> [String; 2] {
    [
        login_fail_key("ip", client_ip),
        login_fail_key("account", username),
    ]
}

/// Whether either the address or the account is currently locked out.
fn signin_locked(keys: &[String; 2]) -> bool {
    login_fails_locked(&keys[0], LOGIN_FAIL_LIMIT)
        || login_fails_locked(&keys[1], ACCOUNT_LOGIN_FAIL_LIMIT)
}

/// Record one failed sign-in against both counters, returning the address count.
fn record_signin_failure(keys: &[String; 2]) -> u32 {
    let address_fails = record_login_fail(&keys[0]);
    record_login_fail(&keys[1]);
    address_fails
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
}

/// Render the wizard again with a failure message.
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
    // The name carries the upload that produced it rather than only the
    // account, so a page that links to a new picture also links to a new URL.
    // A picture served for a year under one unchanging URL is never fetched
    // again, which is how a stored upload ends up invisible.
    let stamp = Utc::now().timestamp_millis().max(0) as u64;
    let sequence = AVATAR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = format!("{user_id}-{stamp:x}-{sequence:x}.png");
    let path = dir.join(&file_name);
    std::fs::write(&path, encoded.into_inner())
        .with_context(|| format!("Failed to write avatar {}", path.display()))?;
    Ok(file_name)
}

/// Counter that keeps two uploads made in the same millisecond from sharing a
/// file name.
static AVATAR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Whether a stored avatar name is a plain file name this handler wrote.
///
/// The name is read back out of the database, so a row naming `../secret` or an
/// absolute path must not turn into a read outside the avatar directory.
fn avatar_file_name_is_safe(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.ends_with(".png")
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

// GET /auth/avatar/{user_id}
pub(crate) async fn serve_avatar(
    State(state): State<AppState>,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
) -> Result<Response> {
    let conn = state.db.get()?;
    let Some(user) = db::find_user_by_id(&conn, user_id)? else {
        return Err(AppError::NotFound("Profil resmi bulunamadı.".into()));
    };

    // The picture is served from the file the row names, not from a name built
    // out of the account id, so a replacement upload is actually the file that
    // gets read.
    let stored = user
        .avatar_file
        .as_deref()
        .filter(|name| avatar_file_name_is_safe(name))
        .and_then(|name| std::fs::read(avatar_dir().join(name)).ok());

    // A missing file is not an error: the account simply uses the generated
    // default avatar. That picture is derived from the account rather than
    // content-addressed, so it revalidates instead of being served immutably.
    let (bytes, policy) = match stored {
        Some(bytes) => (bytes, crate::cache::CACHE_CONTROL_IMMUTABLE_MEDIA),
        None => (
            default_avatar(&user.username)?,
            crate::cache::CACHE_CONTROL_DYNAMIC_PUBLIC,
        ),
    };
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("image/png"),
    );
    crate::cache::set_cache_control(headers, policy);
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

/// The account the settings screen edits, and what it may change.
struct EditableAccount {
    /// Row being edited.
    account: User,
    /// Whether the password form is offered for this identity.
    can_change_password: bool,
}

/// Everything one pass of the settings screen renders.
struct AccountPage {
    /// Row being edited, read for its avatar.
    account: User,
    /// Whether the password form is offered.
    can_change_password: bool,
    /// Boards for the shared header navigation.
    boards: Vec<Board>,
    /// Display name pre-filled into the form, or what the visitor just typed.
    display_name: String,
    /// Username pre-filled into the form, or what the visitor just typed.
    username: String,
    /// Description pre-filled into the form, or what the visitor just typed.
    bio: String,
}

/// Fields collected by the profile form.
struct SubmittedAccount {
    /// Display name the visitor typed.
    display_name: String,
    /// Username the visitor typed.
    username: String,
    /// Short description the visitor typed for their profile.
    bio: String,
    /// Scoped CSRF token.
    csrf: Option<String>,
    /// Optional replacement avatar bytes.
    avatar: Option<Vec<u8>>,
}

/// Values a validated settings form asks the database to store.
struct ProfileChanges {
    /// Trimmed display name.
    display_name: String,
    /// Normalized username, or `None` when the account keeps the one it has.
    username: Option<String>,
    /// Trimmed description, empty when the account cleared it.
    bio: String,
}

/// Resolve the account the settings screen edits for a request.
///
/// A board account edits itself. An operator browses the site under their
/// administrator name, which has no `users` row of its own until the profile
/// route provisions one, so the same lookup hands them that profile and
/// creates it on the spot rather than answering a dead link.
fn editable_account(
    conn: &rusqlite::Connection,
    jar: &CookieJar,
) -> Result<Option<EditableAccount>> {
    if let Some(session_id) = jar.get(USER_SESSION_COOKIE).map(Cookie::value) {
        if let Some(session) = db::get_user_session(conn, session_id)? {
            if let Some(account) = db::find_user_by_id(conn, session.user_id)? {
                return Ok(Some(EditableAccount {
                    account,
                    can_change_password: true,
                }));
            }
        }
    }

    let Some(session_id) = jar.get(ADMIN_SESSION_COOKIE).map(Cookie::value) else {
        return Ok(None);
    };
    let Some(session) = db::get_session(conn, session_id)? else {
        return Ok(None);
    };
    let Some(admin_name) = db::get_admin_name_by_id(conn, session.admin_id)? else {
        return Ok(None);
    };
    let username = admin_name.trim().to_lowercase();
    if username.is_empty() {
        return Ok(None);
    }
    let account = match db::find_user_by_username(conn, &username)? {
        Some(account) => account,
        None => {
            db::ensure_admin_profile(conn, &admin_name)?;
            db::find_user_by_username(conn, &username)?.ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!(
                    "the administrator profile was created but could not be read back"
                ))
            })?
        }
    };
    // The operator's credential lives in `admin_users`. Writing a password on
    // this row would silently turn the operator into an ordinary member on
    // their next sign-in, so the section is hidden instead.
    Ok(Some(EditableAccount {
        account,
        can_change_password: false,
    }))
}

/// Load the account, its edit permissions, and the header navigation.
///
/// `draft` carries what a rejected submission typed so the visitor does not
/// have to type the same values a second time; without it the form opens on
/// the values already saved.
async fn account_page(
    state: &AppState,
    jar: &CookieJar,
    draft: Option<(&str, &str, &str)>,
) -> Result<AccountPage> {
    let jar = jar.clone();
    let draft = draft.map(|(display_name, username, bio)| {
        (display_name.to_owned(), username.to_owned(), bio.to_owned())
    });
    // An operator's profile is provisioned with a real Argon2id hash, so the
    // lookup runs on the blocking pool like every other write.
    let pool = state.db.clone();
    tokio::task::spawn_blocking(move || -> Result<AccountPage> {
        let conn = pool.get()?;
        let Some(EditableAccount {
            account,
            can_change_password,
        }) = editable_account(&conn, &jar)?
        else {
            return Err(AppError::Forbidden(
                "Bu sayfayı görmek için önce giriş yapmalısın.".into(),
            ));
        };
        let boards = db::get_all_boards(&conn)?;
        let (display_name, username, bio) = draft.unwrap_or_else(|| {
            (
                account.display_name.clone(),
                account.username.clone(),
                account.bio.clone(),
            )
        });
        Ok(AccountPage {
            account,
            can_change_password,
            boards,
            display_name,
            username,
            bio,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?
}

#[cfg(test)]
/// Tests for the account settings screen, kept beside the validation they
/// cover rather than at the end of the file with the other unit tests.
mod account_settings_tests {
    use super::{validate_profile_changes, SubmittedAccount};
    use crate::templates::auth::{account_menu_html, AccountMenu};

    /// A settings submission with the given field values.
    fn submission(display_name: &str, username: &str, bio: &str) -> SubmittedAccount {
        SubmittedAccount {
            display_name: display_name.to_owned(),
            username: username.to_owned(),
            bio: bio.to_owned(),
            csrf: None,
            avatar: None,
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the test asserts on the validated values, so a rejected form must fail the test immediately"
    )]
    /// The settings form stores a trimmed display name and only renames the
    /// account when the typed username actually differs from the saved one.
    fn profile_changes_rename_only_when_the_username_really_changed() {
        let unchanged =
            validate_profile_changes(&submission("  Anonim  ", "anon", "selam"), "anon")
                .expect("a valid unchanged form is accepted");
        assert_eq!(unchanged.display_name, "Anonim");
        assert_eq!(
            unchanged.username, None,
            "keeping the current username must not ask for a rename"
        );

        let renamed =
            validate_profile_changes(&submission("Anonim", "  Yeni-Ad ", "selam"), "anon")
                .expect("a valid rename is accepted");
        assert_eq!(
            renamed.username.as_deref(),
            Some("yeni-ad"),
            "a typed username is normalized the way registration normalizes it"
        );
    }

    #[test]
    /// An empty, overlong, or unusable value is rejected with a message, and
    /// a form that renames to a different valid name is accepted.
    fn profile_changes_reject_a_name_the_account_cannot_use() {
        assert!(validate_profile_changes(&submission("   ", "anon", "selam"), "anon").is_err());
        assert!(
            validate_profile_changes(&submission(&"a".repeat(41), "anon", "selam"), "anon").is_err()
        );
        assert!(validate_profile_changes(&submission("Anonim", "bir iki", "selam"), "anon").is_err());
        assert!(validate_profile_changes(&submission("Anonim", "", "selam"), "anon").is_err());
        assert!(validate_profile_changes(&submission("Anonim", "anon", "selam"), "anon").is_ok());
    }

    #[test]
    /// The description is trimmed and may be cleared, because an account is
    /// allowed to have no line on its profile; only an overlong one is refused.
    fn profile_changes_allow_the_description_to_be_written_and_cleared() {
        let written =
            validate_profile_changes(&submission("Anonim", "anon", "  merhaba dunya  "), "anon")
                .expect("a description within the bound is accepted");
        assert_eq!(written.bio, "merhaba dunya");

        let cleared = validate_profile_changes(&submission("Anonim", "anon", "   "), "anon")
            .expect("an empty description clears the line rather than failing");
        assert_eq!(cleared.bio, "");

        assert!(
            validate_profile_changes(&submission("Anonim", "anon", &"a".repeat(281)), "anon")
                .is_err(),
            "an overlong description is a rejected form, not a silent cut"
        );
    }

    #[test]
    /// The header account menu's second entry opens the settings screen, so
    /// "Profili Düzenle" is a real link rather than the inert label it was.
    fn account_menu_links_the_settings_screen() {
        let menu = AccountMenu {
            display_name: "Anonim".to_owned(),
            username: "anon".to_owned(),
            is_admin: false,
            user_id: None,
            avatar_file: None,
        };
        let html = account_menu_html(Some(&menu), "token");
        assert!(
            html.contains(r#"<a class="account-menu-item" href="/account/edit">"#),
            "the settings entry has to be a real link, got {html}"
        );
        assert!(
            !html.contains("is-disabled"),
            "no account menu entry is inert any more, got {html}"
        );
    }
}

/// Render one pass of the account settings screen.
async fn render_account_edit(
    state: &AppState,
    page: AccountPage,
    jar: CookieJar,
    headers: &HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    notice: AccountSettingsNotice,
) -> Result<Response> {
    let secure = crate::handlers::admin::should_set_secure_cookie(headers, secure_context);
    let theme = crate::handlers::board::current_theme_from_jar(&jar);
    let preferences = crate::handlers::board::user_preferences_from_jar(&jar);
    // The header's sign-out control is scoped to sign-in, and the header's own
    // controls are scoped to the site-wide cookie, so the screen carries three
    // tokens: one for the shared layout, one for the settings forms, and the
    // one the account menu already asks every page for.
    let (menu, menu_csrf, jar) = account_menu_for_request(state, jar, secure)?;
    let (jar, layout_csrf) =
        crate::handlers::board::ensure_csrf_for_request(jar, headers, secure_context);
    let (jar, form_csrf) = ensure_user_csrf(jar, secure, ACCOUNT_CSRF_SCOPE);
    let account_menu = templates::auth::account_menu_html(menu.as_ref(), &menu_csrf);

    let settings = AccountSettings {
        display_name: page.display_name,
        username: page.username,
        bio: page.bio,
        user_id: page.account.id,
        has_avatar: page.account.avatar_file.is_some(),
        avatar_version: templates::auth::avatar_version(page.account.avatar_file.as_deref()),
        can_change_password: page.can_change_password,
    };
    let html = templates::auth::account_settings_page(
        &settings,
        &page.boards,
        theme.as_deref(),
        preferences,
        &AccountSettingsTokens {
            layout: layout_csrf,
            form: form_csrf,
        },
        &account_menu,
        &notice,
    );
    Ok((jar, Html(html)).into_response())
}

/// Render the settings screen again with a failure message.
async fn render_account_edit_failure(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    draft: Option<(&str, &str, &str)>,
    message: &str,
) -> Result<Response> {
    let page = account_page(state, &jar, draft).await?;
    render_account_edit(
        state,
        page,
        jar,
        headers,
        secure_context,
        AccountSettingsNotice::failed(message),
    )
    .await
}

// GET /account/edit
pub(crate) async fn account_edit_page(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    Query(query): Query<AccountEditQuery>,
) -> Result<Response> {
    let page = account_page(&state, &jar, None).await?;
    let notice = match query.saved.as_deref() {
        Some("profile") => AccountSettingsNotice::saved("Profil bilgilerin güncellendi."),
        Some("password") => AccountSettingsNotice::saved("Parolan değiştirildi."),
        _ => AccountSettingsNotice::empty(),
    };
    render_account_edit(&state, page, jar, &headers, secure_context, notice).await
}

/// Validate the settings form's fields before anything is written.
///
/// A rejected value is a message for the visitor rather than a failure, so the
/// screen can be rendered again around it with the typed values intact.
fn validate_profile_changes(
    submitted: &SubmittedAccount,
    current_username: &str,
) -> std::result::Result<ProfileChanges, String> {
    let display_name = submitted.display_name.trim();
    if display_name.is_empty() {
        return Err(format!("{DISPLAY_NAME_FIELD_LABEL} boş bırakılamaz."));
    }
    if display_name.chars().count() > DISPLAY_NAME_MAX_CHARS {
        return Err(format!(
            "{DISPLAY_NAME_FIELD_LABEL} en fazla {DISPLAY_NAME_MAX_CHARS} karakter olabilir."
        ));
    }

    let username = normalize_username(&submitted.username);
    if !username_is_well_formed(&username) {
        return Err(format!(
            "{USERNAME_FIELD_LABEL} yalnızca harf, rakam, `_`, `-` ve `.` içerebilir; en fazla {USERNAME_MAX_CHARS} karakter."
        ));
    }
    // Renaming to the name the account already has is a no-op rather than a
    // conflict with itself.
    let username = (username != current_username).then_some(username);

    // The description is optional, so an empty one clears the line rather than
    // failing, but an overlong one is a rejected form and not a silent cut.
    let bio = submitted.bio.trim();
    if bio.chars().count() > BIO_MAX_CHARS {
        return Err(format!("Biyografi en fazla {BIO_MAX_CHARS} karakter olabilir."));
    }
    Ok(ProfileChanges {
        display_name: display_name.to_owned(),
        username,
        bio: bio.to_owned(),
    })
}

/// Decode and store the replacement avatar a settings form carries.
///
/// An absent file is not a change: the account keeps the picture it already
/// has, so renaming an account never asks for a file. A file that is present
/// still has to be a real image within the size bound, and one that fails
/// either test is a message for the visitor rather than a half-applied change.
fn store_replacement_avatar(
    user_id: i64,
    submitted: &SubmittedAccount,
) -> std::result::Result<Option<String>, String> {
    let Some(bytes) = submitted.avatar.as_deref().filter(|bytes| !bytes.is_empty()) else {
        return Ok(None);
    };
    if bytes.len() > AVATAR_MAX_BYTES {
        return Err("Profil resmi en fazla 2 MiB olabilir.".to_owned());
    }
    match store_avatar(user_id, bytes) {
        Ok(file_name) => Ok(Some(file_name)),
        Err(error) => {
            tracing::warn!(target: "auth", user_id, "Avatar upload rejected: {error}");
            Err("Profil resmi okunamadı. PNG, JPEG, GIF, WebP, BMP ya da TIFF denemelisin."
                .to_owned())
        }
    }
}

// POST /account/profile
pub(crate) async fn account_profile_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    multipart: Multipart,
) -> Result<Response> {
    let submitted = read_account_multipart(multipart).await?;
    let csrf_valid = validate_form_csrf(&jar, ACCOUNT_CSRF_SCOPE, submitted.csrf.as_deref());
    require_same_origin(&headers, secure_context.peer, csrf_valid)?;
    if !csrf_valid {
        return Err(AppError::Forbidden("CSRF token mismatch.".into()));
    }

    let draft = Some((
        submitted.display_name.as_str(),
        submitted.username.as_str(),
        submitted.bio.as_str(),
    ));
    let page = account_page(&state, &jar, None).await?;
    let user_id = page.account.id;
    let replaced_avatar = page.account.avatar_file.clone();
    let changes = match validate_profile_changes(&submitted, &page.account.username) {
        Ok(changes) => changes,
        Err(message) => {
            return Ok(
                render_account_edit_failure(&state, jar, &headers, secure_context, draft, &message)
                    .await?,
            );
        }
    };

    // The picture is decoded and written before the row is touched, so a file
    // the visitor cannot use is reported without a half-renamed account.
    let stored_avatar = match store_replacement_avatar(user_id, &submitted) {
        Ok(stored) => stored,
        Err(message) => {
            return Ok(render_account_edit_failure(
                &state,
                jar,
                &headers,
                secure_context,
                draft,
                &message,
            )
            .await?);
        }
    };

    // The rename, the picture, the display name, and the description are one
    // write: a unique index is the final authority on a taken username, so a
    // rename that races another account is rejected rather than half-applied.
    let pool = state.db.clone();
    let renamed = tokio::task::spawn_blocking(move || -> Result<bool> {
        let conn = pool.get()?;
        if let Some(username) = changes.username.as_deref() {
            if db::username_exists(&conn, username)? {
                return Ok(false);
            }
            if let Err(error) = db::update_username(&conn, user_id, username) {
                if is_unique_violation(&error) {
                    tracing::debug!(target: "auth", "username taken during rename");
                    return Ok(false);
                }
                return Err(AppError::from(error));
            }
        }
        if let Some(file_name) = stored_avatar.as_deref() {
            db::set_user_avatar(&conn, user_id, file_name)?;
        }
        db::update_display_name(&conn, user_id, &changes.display_name)?;
        db::update_bio(&conn, user_id, &changes.bio)?;
        Ok(true)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    if !renamed {
        return Ok(render_account_edit_failure(
            &state,
            jar,
            &headers,
            secure_context,
            draft,
            "Bu kullanıcı adı zaten alınmış.",
        )
        .await?);
    }

    // The replaced picture is only dropped once the new row is committed, so a
    // rejected change never leaves the account without a picture.
    if let Some(previous) = replaced_avatar {
        remove_stored_avatar(&previous);
    }

    tracing::info!(target: "auth", user_id, "Account profile updated");
    Ok((jar, Redirect::to("/account/edit?saved=profile")).into_response())
}

/// Remove a picture an account no longer points at, best effort.
///
/// A file that is already gone, or that a name from the database turned out not
/// to be a plain file, is not worth failing a save over.
fn remove_stored_avatar(file_name: &str) {
    if !avatar_file_name_is_safe(file_name) {
        return;
    }
    if let Err(error) = std::fs::remove_file(avatar_dir().join(file_name)) {
        tracing::debug!(target: "auth", "Replaced avatar not removed: {error}");
    }
}

// POST /account/password
pub(crate) async fn account_password_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    Form(form): Form<PasswordChangeForm>,
) -> Result<Response> {
    let csrf_valid = validate_form_csrf(&jar, ACCOUNT_CSRF_SCOPE, form.csrf.as_deref());
    require_same_origin(&headers, secure_context.peer, csrf_valid)?;
    if !csrf_valid {
        return Err(AppError::Forbidden("CSRF token mismatch.".into()));
    }

    let page = account_page(&state, &jar, None).await?;
    if !page.can_change_password {
        return Err(AppError::Forbidden(
            "Parola değiştirme yalnızca kayıt olmuş üyeler için.".into(),
        ));
    }
    let user_id = page.account.id;

    if form.password.chars().count() < PASSWORD_MIN_CHARS {
        return Ok(render_account_edit_failure(
            &state,
            jar,
            &headers,
            secure_context,
            None,
            &format!("Parola en az {PASSWORD_MIN_CHARS} karakter olmalı."),
        )
        .await?);
    }
    if form.password.chars().count() > PASSWORD_MAX_CHARS {
        return Ok(render_account_edit_failure(
            &state,
            jar,
            &headers,
            secure_context,
            None,
            "Parola çok uzun.",
        )
        .await?);
    }
    if form.password != form.password_confirm {
        return Ok(render_account_edit_failure(
            &state,
            jar,
            &headers,
            secure_context,
            None,
            "Parolalar eşleşmiyor.",
        )
        .await?);
    }

    // Argon2 is deliberately expensive, so both the verification of the current
    // password and the hash of its replacement run on the blocking pool.
    let pool = state.db.clone();
    let current = form.current_password;
    let chosen = form.password.clone();
    let current_hash = page.account.password_hash;
    let replaced = tokio::task::spawn_blocking(move || -> Result<bool> {
        if !verify_password(&current, &current_hash)? {
            return Ok(false);
        }
        let new_hash = hash_password(&chosen)?;
        let conn = pool.get()?;
        db::update_password_hash(&conn, user_id, &new_hash)?;
        // Every session this account holds, including the one making the
        // request, was opened with the password that just stopped being
        // valid. The requester is signed in again below on a fresh id.
        db::delete_user_sessions_for_user(&conn, user_id)?;
        Ok(true)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    if !replaced {
        return Ok(render_account_edit_failure(
            &state,
            jar,
            &headers,
            secure_context,
            None,
            "Mevcut parola hatalı.",
        )
        .await?);
    }

    // Signing in again here mints a new session id. The cookie the visitor was
    // holding is dead, so a value an attacker planted before the change cannot
    // ride along across it.
    tracing::info!(target: "auth", user_id, "Account password changed");
    let secure = crate::handlers::admin::should_set_secure_cookie(&headers, secure_context);
    issue_session(state, jar, user_id, secure, "/account/edit?saved=password").await
}

/// Read the settings form's multipart body, bounding every field.
async fn read_account_multipart(mut multipart: Multipart) -> Result<SubmittedAccount> {
    let mut out = SubmittedAccount {
        display_name: String::new(),
        username: String::new(),
        bio: String::new(),
        csrf: None,
        avatar: None,
    };

    loop {
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
                "bio" => out.bio = value,
                "_csrf" => out.csrf = Some(value),
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
    // The sign-in screen carries the page the visitor asked for, so signing in
    // puts them back on it rather than on the front page they never chose.
    Ok(Redirect::to(&login_url_for(request.uri().path())).into_response())
}

/// The sign-in URL that sends the visitor back to `wanted` afterwards.
fn login_url_for(wanted: &str) -> String {
    if wanted == "/" {
        return String::from("/login");
    }
    format!(
        "/login?return_to={}",
        crate::utils::redirect::encode_query_component(wanted)
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{avatar_initial, default_avatar, login_url_for, AVATAR_EDGE};

    #[test]
    /// The gate has to hand the visitor the page they asked for, or signing
    /// in drops them somewhere they never chose.
    fn the_sign_in_url_carries_the_page_the_visitor_asked_for() {
        assert_eq!(login_url_for("/"), "/login");
        assert_eq!(login_url_for("/b/"), "/login?return_to=%2Fb%2F");
        assert_eq!(
            login_url_for("/b/thread/12?page=2"),
            "/login?return_to=%2Fb%2Fthread%2F12%3Fpage%3D2"
        );
        // A path is the whole of what may travel, so a value that is not one
        // cannot smuggle a second host into the query.
        assert!(!login_url_for("//evil.example/").contains("//evil"));
    }

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

#[cfg(test)]
/// The stored picture has to come back out of the file the row names, and a
/// locked-out sign-in has to stay locked until it is cleared.
mod avatar_and_signin_tests {
    use super::{
        avatar_dir, avatar_file_name_is_safe, clear_login_fails, record_login_fail, serve_avatar,
        signin_fail_keys, signin_locked, store_avatar, ACCOUNT_LOGIN_FAIL_LIMIT, LOGIN_FAIL_LIMIT,
    };
    use crate::{cache, db, error::Result};
    use axum::body::to_bytes;
    use axum::extract::{Path, State};
    use axum::http::header;

    /// A small solid-colour PNG, standing in for an uploaded picture.
    #[expect(
        clippy::expect_used,
        reason = "the test asserts on the encoded bytes, so a failed encode must fail the test immediately"
    )]
    fn uploaded_png() -> Vec<u8> {
        let picture = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            8,
            8,
            image::Rgba([200, 30, 30, 255]),
        ));
        let mut encoded = std::io::Cursor::new(Vec::new());
        picture
            .write_to(&mut encoded, image::ImageFormat::Png)
            .expect("the test picture should encode as a PNG");
        encoded.into_inner()
    }

    /// Read one header of a response as a string.
    fn header_of(response: &axum::response::Response, name: header::HeaderName) -> String {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A stored upload is served from the file the row names, and the file is
    /// named after the upload rather than only the account, so a replacement
    /// picture is a different file instead of an overwritten one.
    async fn a_stored_upload_is_served_from_the_file_the_row_names() -> Result<()> {
        let state = crate::test_support::app_state();
        let conn = state.db.get()?;
        let user_id = db::create_user(&conn, "avataruser", "Avatar", "hash", None, "")?;
        let file_name = store_avatar(user_id, &uploaded_png())?;
        db::set_user_avatar(&conn, user_id, &file_name)?;
        let path = avatar_dir().join(&file_name);

        let response = serve_avatar(State(state), Path(user_id)).await?;

        assert_eq!(header_of(&response, header::CONTENT_TYPE), "image/png");
        assert_eq!(
            header_of(&response, header::CACHE_CONTROL),
            cache::CACHE_CONTROL_IMMUTABLE_MEDIA,
            "a stored picture sits at a URL that changes with the upload, so it may be kept for a year"
        );
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        assert_eq!(
            body.as_ref(),
            std::fs::read(&path)?,
            "the bytes served are the bytes the upload wrote"
        );
        assert!(
            file_name.starts_with(&format!("{user_id}-")) && file_name.ends_with(".png"),
            "an upload is stored under its own name, got {file_name}"
        );

        let _ignored = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// The drawn placeholder is derived from the account rather than
    /// content-addressed, so it revalidates instead of being pinned in a cache
    /// for a year under a URL that never changes.
    async fn an_account_without_an_upload_revalidates_its_placeholder() -> Result<()> {
        let state = crate::test_support::app_state();
        let conn = state.db.get()?;
        let user_id = db::create_user(&conn, "avatarless", "Avatarless", "hash", None, "")?;

        let response = serve_avatar(State(state), Path(user_id)).await?;

        assert_eq!(
            header_of(&response, header::CACHE_CONTROL),
            cache::CACHE_CONTROL_DYNAMIC_PUBLIC
        );
        Ok(())
    }

    #[test]
    /// A name read back out of the database is only ever treated as a plain
    /// file inside the avatar directory, so a row naming something else cannot
    /// turn the picture route into an arbitrary file read.
    fn a_stored_name_cannot_point_outside_the_avatar_directory() {
        assert!(avatar_file_name_is_safe("12-1a2b3c4d5e6f-0.png"));
        for name in [
            "../secret.png",
            "../../etc/passwd.png",
            "12/avatar.png",
            "/etc/avatar.png",
            ".hidden.png",
            "avatar.jpg",
            "",
        ] {
            assert!(
                !avatar_file_name_is_safe(name),
                "{name:?} must not be read as an avatar file"
            );
        }
    }

    #[test]
    /// Failures add up: the address is locked out once its budget is spent, and
    /// a sign-in that finally succeeds clears what it followed.
    fn repeated_failures_lock_the_address_until_a_sign_in_succeeds() {
        let keys = signin_fail_keys("203.0.113.9", "anon");
        clear_login_fails(&keys);
        assert!(!signin_locked(&keys), "a first attempt is never locked out");
        for _ in 0..LOGIN_FAIL_LIMIT {
            record_login_fail(&keys[0]);
            record_login_fail(&keys[1]);
        }
        assert!(
            signin_locked(&keys),
            "one address spending its whole budget is locked out"
        );
        clear_login_fails(&keys);
        assert!(
            !signin_locked(&keys),
            "a real sign-in clears the failures that came before it"
        );
    }

    #[test]
    /// Counting per address alone is not enough: the same name guessed from a
    /// fresh address each time still runs out of budget on the account.
    fn one_name_guessed_from_many_addresses_still_locks_the_account() {
        for index in 0..ACCOUNT_LOGIN_FAIL_LIMIT {
            let keys = signin_fail_keys(&format!("198.51.100.{index}"), "hedef");
            assert!(!signin_locked(&keys));
            record_login_fail(&keys[0]);
            record_login_fail(&keys[1]);
        }
        let spread = signin_fail_keys("198.51.100.240", "hedef");
        assert!(
            signin_locked(&spread),
            "each address is under its own budget, but the account is not"
        );
        clear_login_fails(&spread);
    }
}
