//! The administration panel's account-management handlers.
//!
//! Two identities can reach this section. An operator signed in through
//! `/admin/login` holds an operator session and is treated as the owner, which
//! is what the command line has always meant. A board account that carries a
//! staff role reaches it with its own account session and is limited to what
//! that role's permissions allow. Both paths run the same checks and write the
//! same audit record, so an account action is logged the same way whoever made
//! it.

use crate::db;
use crate::error::{AppError, Result};
use crate::models::{Pagination, User};
use crate::roles::{AccountStatus, Permission, UserRole, MAX_SUSPEND_SECS};
use crate::templates;
use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse as _, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use std::net::SocketAddr;

use super::AppState;

/// Accounts shown on one page of the listing.
const USERS_PER_PAGE: i64 = 25;
/// Longest username the board accepts, matching registration.
const USERNAME_MAX_CHARS: usize = 20;
/// Longest display name the board accepts, matching registration.
const DISPLAY_NAME_MAX_CHARS: usize = 40;
/// Shortest password an operator may set, matching registration.
const PASSWORD_MIN_CHARS: usize = 6;
/// Longest password an operator may set, matching registration.
const PASSWORD_MAX_CHARS: usize = 256;

/// Who is making the request, and what their role allows.
struct ActingStaff {
    /// Name recorded in the audit log.
    name: String,
    /// The role whose permissions bound this request.
    role: UserRole,
    /// Row recorded in the audit log: the account's own id for a role-based
    /// member, the operator's id for a command-line operator.
    audit_id: i64,
}

impl ActingStaff {
    /// Refuse the request unless the acting role carries `permission`.
    fn require(&self, permission: Permission, message: &str) -> Result<()> {
        if self.role.has(permission) {
            Ok(())
        } else {
            Err(AppError::Forbidden(message.into()))
        }
    }
}

/// Resolve the identity behind a request, or refuse it.
///
/// The operator session is checked first because it is the stronger thing: it
/// exists only for identities created from the command line, which are the
/// site's operators by definition. Failing that, the request must carry a
/// board account whose stored role reaches the panel.
fn acting_staff(conn: &rusqlite::Connection, jar: &CookieJar) -> Result<ActingStaff> {
    if let Some(session_id) = jar.get(super::SESSION_COOKIE).map(Cookie::value) {
        if let Some(session) = db::get_session(conn, session_id)? {
            let name =
                db::get_admin_name_by_id(conn, session.admin_id)?.unwrap_or_else(|| "operator".to_owned());
            return Ok(ActingStaff {
                name,
                role: UserRole::Owner,
                audit_id: session.admin_id,
            });
        }
    }

    let Some(session_id) = jar
        .get(crate::handlers::auth::USER_SESSION_COOKIE)
        .map(Cookie::value)
    else {
        return Err(AppError::Forbidden("Bu bölüm için yetkin yok.".into()));
    };
    let session = db::get_user_session(conn, session_id)?
        .ok_or_else(|| AppError::Forbidden("Oturum süresi dolmuş.".into()))?;
    let account = db::find_user_by_id(conn, session.user_id)?
        .ok_or_else(|| AppError::Forbidden("Hesap bulunamadı.".into()))?;
    if !account.role.reaches_admin_panel() {
        return Err(AppError::Forbidden("Bu bölüm için yetkin yok.".into()));
    }
    Ok(ActingStaff {
        audit_id: account.id,
        name: account.username.clone(),
        role: account.role,
    })
}

/// Query params accepted by the listing.
#[derive(Deserialize)]
pub(in crate::server) struct UsersQuery {
    /// Page number, one-based.
    #[serde(default)]
    page: Option<i64>,
    /// Optional name or username fragment.
    q: Option<String>,
    /// Message left by a previous action.
    flash: Option<String>,
    /// Failure message left by a previous action.
    flash_error: Option<String>,
}

/// Form for renaming an account.
#[derive(Deserialize)]
pub(in crate::server) struct RenameForm {
    /// Row the action applies to.
    user_id: i64,
    /// Name shown on posts and profiles.
    display_name: String,
    /// Unique login name.
    username: String,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Form for setting a new password.
#[derive(Deserialize)]
pub(in crate::server) struct PasswordForm {
    /// Row the action applies to.
    user_id: i64,
    /// Replacement password, typed into a field that is never echoed back.
    password: String,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Form for changing a staff role.
#[derive(Deserialize)]
pub(in crate::server) struct RoleForm {
    /// Row the action applies to.
    user_id: i64,
    /// Requested role name.
    role: String,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Form for suspending an account for a while.
#[derive(Deserialize)]
pub(in crate::server) struct SuspendForm {
    /// Row the action applies to.
    user_id: i64,
    /// How long to suspend for, in hours.
    hours: i64,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Form for an action that only names its target.
#[derive(Deserialize)]
pub(in crate::server) struct UserActionForm {
    /// Row the action applies to.
    user_id: i64,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Reject a state change whose request failed the origin or token check.
fn require_post_authorization(
    jar: &CookieJar,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    form_token: Option<&str>,
) -> Result<()> {
    crate::handlers::board::check_csrf_jar(jar, form_token)?;
    super::require_same_origin_request(headers, peer)
}

/// Load the account an action targets, or report that it is gone.
fn target_account(conn: &rusqlite::Connection, user_id: i64) -> Result<User> {
    db::find_user_by_id(conn, user_id)?
        .ok_or_else(|| AppError::NotFound("Hesap bulunamadı.".into()))
}

/// Record an account action in the moderation log.
///
/// A failure to write the audit line is logged loudly rather than rolled back:
/// the action itself is what the operator asked for, and losing the record must
/// not quietly undo it.
fn audit(conn: &rusqlite::Connection, staff: &ActingStaff, action: &str, target: i64, detail: &str) {
    if let Err(error) = db::log_mod_action(
        conn,
        staff.audit_id,
        &staff.name,
        action,
        "user",
        Some(target),
        "",
        detail,
    ) {
        tracing::error!(
            target: "admin",
            actor = %staff.name,
            user_id = target,
            action,
            error = %error,
            "Account action completed without an audit-log record"
        );
    }
}

/// Redirect back to the listing with a message the operator can read.
///
/// The redirect is turned into a response here rather than at each call site,
/// so an action handler returns the same type whatever it decided.
fn back_to_users(message: &str, is_error: bool) -> Response {
    let key = if is_error { "flash_error" } else { "flash" };
    Redirect::to(&format!(
        "/admin/users?{key}={}",
        crate::utils::redirect::encode_query_component(message)
    ))
    .into_response()
}

/// Whether a role change was applied, and what the operator is told.
enum RoleOutcome {
    /// The role was written.
    Applied(&'static str),
    /// The change was refused, and nothing was written.
    Refused,
}

/// A username an operator may set, or the reason it cannot be one.
fn validate_username(raw: &str) -> Result<String> {
    let username = raw.trim().to_lowercase();
    if username.is_empty()
        || username.chars().count() > USERNAME_MAX_CHARS
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(AppError::BadRequest(
            "Kullanıcı adı boş olamaz, 20 karakteri geçemez ve sadece harf, rakam, _ , - , . içerebilir."
                .into(),
        ));
    }
    Ok(username)
}

/// A display name an operator may set, or the reason it cannot be one.
fn validate_display_name(raw: &str) -> Result<String> {
    let display_name = raw.trim().to_owned();
    if display_name.is_empty() || display_name.chars().count() > DISPLAY_NAME_MAX_CHARS {
        return Err(AppError::BadRequest(
            "İsim boş olamaz veya 40 karakteri geçemez.".into(),
        ));
    }
    Ok(display_name)
}

/// Build the listing page.
async fn render_users(
    state: AppState,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    query: UsersQuery,
) -> Result<Response> {
    let search = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .map(str::to_owned)
        .unwrap_or_default();
    let page = query.page.unwrap_or(1).max(1);
    let flash = query
        .flash
        .as_deref()
        .map(|message| (message.to_owned(), false))
        .or_else(|| {
            query
                .flash_error
                .as_deref()
                .map(|message| (message.to_owned(), true))
        });

    let (jar, csrf) = crate::handlers::board::ensure_csrf_for_request(jar, &headers, secure_context);
    let current_theme = crate::handlers::board::current_theme_from_jar(&jar);
    let pool = state.db.clone();
    let scoped_jar = jar.clone();

    let html = tokio::task::spawn_blocking(move || -> Result<String> {
        let conn = pool.get()?;
        let staff = acting_staff(&conn, &scoped_jar)?;
        let (rows, total) = if search.is_empty() {
            (
                db::list_users(&conn, USERS_PER_PAGE, (page - 1) * USERS_PER_PAGE)?,
                db::count_users(&conn)?,
            )
        } else {
            (
                db::search_users(&conn, &search, USERS_PER_PAGE)?,
                db::count_users_matching(&conn, Some(&search))?,
            )
        };
        let now = chrono::Utc::now().timestamp();
        let prepared: Vec<_> = rows
            .into_iter()
            .map(|account| templates::admin::AdminUserRow::new(account, now))
            .collect();
        let pagination = Pagination::new(page, USERS_PER_PAGE, total);
        let boards = db::get_all_boards(&conn)?;
        let view = templates::admin::AdminUsersView {
            rows: &prepared,
            pagination: &pagination,
            search: &search,
            flash: flash.as_ref(),
            csrf_token: &csrf,
            acting_role: staff.role,
            boards: &boards,
            current_theme: current_theme.as_deref(),
        };
        Ok(templates::admin::admin_users_page(&view))
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    Ok((jar, Html(html)).into_response())
}

// GET /admin/users
pub(in crate::server) async fn admin_users(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    secure_context: crate::middleware::SecureCookieContext,
    Query(query): Query<UsersQuery>,
) -> Result<Response> {
    render_users(state, jar, headers, secure_context, query).await
}

// POST /admin/users/rename
pub(in crate::server) async fn admin_user_rename(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Form(form): Form<RenameForm>,
) -> Result<Response> {
    require_post_authorization(&jar, &headers, Some(peer), form.csrf.as_deref())?;
    let display_name = match validate_display_name(&form.display_name) {
        Ok(name) => name,
        Err(error) => return Ok(back_to_users(&error.to_string(), true)),
    };
    let username = match validate_username(&form.username) {
        Ok(name) => name,
        Err(error) => return Ok(back_to_users(&error.to_string(), true)),
    };

    let user_id = form.user_id;
    let scoped_jar = jar.clone();
    let pool = state.db.clone();
    let renamed = tokio::task::spawn_blocking(move || -> Result<bool> {
        let conn = pool.get()?;
        let staff = acting_staff(&conn, &scoped_jar)?;
        staff.require(Permission::RenameAccount, "Bu işlem için yetkin yok.")?;
        let account = target_account(&conn, user_id)?;
        if account.username != username && db::username_exists(&conn, &username)? {
            return Ok(false);
        }
        db::update_display_name(&conn, user_id, &display_name)?;
        db::update_username(&conn, user_id, &username)?;
        audit(&conn, &staff, "user_rename", user_id, "names changed");
        Ok(true)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    return Ok(match renamed? {
        true => back_to_users("Hesabın isimleri güncellendi.", false),
        false => back_to_users("Bu kullanıcı adı zaten alınmış.", true),
    });
}

// POST /admin/users/password
pub(in crate::server) async fn admin_user_password(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Form(form): Form<PasswordForm>,
) -> Result<Response> {
    require_post_authorization(&jar, &headers, Some(peer), form.csrf.as_deref())?;
    if form.password.chars().count() < PASSWORD_MIN_CHARS
        || form.password.chars().count() > PASSWORD_MAX_CHARS
    {
        return Ok(back_to_users("Parola 6 ile 256 karakter arasında olmalı.", true));
    }

    let user_id = form.user_id;
    let password = form.password;
    let scoped_jar = jar.clone();
    let pool = state.db.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        let staff = acting_staff(&conn, &scoped_jar)?;
        staff.require(
            Permission::ResetAccountPassword,
            "Parola değiştirme yetkin yok.",
        )?;
        target_account(&conn, user_id)?;
        let hash = crate::utils::crypto::hash_password(&password)?;
        db::update_password_hash(&conn, user_id, &hash)?;
        // The replaced password is no longer valid, so neither is anything it
        // opened. The account signs in again on the new one.
        db::delete_user_sessions_for_user(&conn, user_id)?;
        audit(&conn, &staff, "user_password", user_id, "credential replaced");
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    Ok(back_to_users("Parola değiştirildi ve oturumları kapatıldı.", false))
}

// POST /admin/users/role
pub(in crate::server) async fn admin_user_role(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Form(form): Form<RoleForm>,
) -> Result<Response> {
    require_post_authorization(&jar, &headers, Some(peer), form.csrf.as_deref())?;
    let user_id = form.user_id;
    let requested = UserRole::from_stored(&form.role);
    let scoped_jar = jar.clone();
    let pool = state.db.clone();

    let outcome = tokio::task::spawn_blocking(move || -> Result<RoleOutcome> {
        let conn = pool.get()?;
        let staff = acting_staff(&conn, &scoped_jar)?;
        staff.require(Permission::AssignRoles, "Rol verme yetkin yok.")?;
        let account = target_account(&conn, user_id)?;

        // Ownership is the one grant that cannot come from below: only the
        // owner hands it out, and only the owner takes it back.
        if requested == UserRole::Owner && staff.role != UserRole::Owner {
            return Ok(RoleOutcome::Refused);
        }
        if account.role == UserRole::Owner && staff.role != UserRole::Owner {
            return Ok(RoleOutcome::Refused);
        }
        // The site keeps one owner. Removing the last one would leave nobody
        // able to appoint a replacement.
        if account.role == UserRole::Owner
            && requested != UserRole::Owner
            && db::count_users_with_role(&conn, UserRole::Owner)? <= 1
        {
            return Ok(RoleOutcome::Refused);
        }
        db::set_user_role(&conn, user_id, requested)?;
        audit(
            &conn,
            &staff,
            "user_role",
            user_id,
            &format!("role set to {}", requested.as_str()),
        );
        Ok(RoleOutcome::Applied("Rol güncellendi."))
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    return Ok(match outcome? {
        RoleOutcome::Applied(message) => back_to_users(message, false),
        RoleOutcome::Refused => back_to_users("Bu rol değişikliği yapılamaz.", true),
    });
}

// POST /admin/users/suspend
pub(in crate::server) async fn admin_user_suspend(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Form(form): Form<SuspendForm>,
) -> Result<Response> {
    require_post_authorization(&jar, &headers, Some(peer), form.csrf.as_deref())?;
    let hours = form.hours.clamp(1, MAX_SUSPEND_SECS / 3600);
    let user_id = form.user_id;
    let scoped_jar = jar.clone();
    let pool = state.db.clone();

    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        let staff = acting_staff(&conn, &scoped_jar)?;
        staff.require(Permission::SuspendAccount, "Askıya alma yetkin yok.")?;
        target_account(&conn, user_id)?;
        let until = chrono::Utc::now().timestamp() + hours * 3600;
        db::set_user_status(&conn, user_id, AccountStatus::Suspended, Some(until))?;
        audit(
            &conn,
            &staff,
            "user_suspend",
            user_id,
            &format!("suspended for {hours}h"),
        );
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    Ok(back_to_users("Hesap askıya alındı.", false))
}

// POST /admin/users/lift
pub(in crate::server) async fn admin_user_lift(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Form(form): Form<UserActionForm>,
) -> Result<Response> {
    require_post_authorization(&jar, &headers, Some(peer), form.csrf.as_deref())?;
    let user_id = form.user_id;
    let scoped_jar = jar.clone();
    let pool = state.db.clone();

    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        let staff = acting_staff(&conn, &scoped_jar)?;
        staff.require(Permission::SuspendAccount, "Askı kaldırma yetkin yok.")?;
        target_account(&conn, user_id)?;
        db::set_user_status(&conn, user_id, AccountStatus::Active, None)?;
        audit(&conn, &staff, "user_unsuspend", user_id, "suspension lifted");
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    Ok(back_to_users("Askı kaldırıldı.", false))
}

// POST /admin/users/ban
pub(in crate::server) async fn admin_user_ban(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Form(form): Form<UserActionForm>,
) -> Result<Response> {
    require_post_authorization(&jar, &headers, Some(peer), form.csrf.as_deref())?;
    let user_id = form.user_id;
    let scoped_jar = jar.clone();
    let pool = state.db.clone();

    let refused = tokio::task::spawn_blocking(move || -> Result<bool> {
        let conn = pool.get()?;
        let staff = acting_staff(&conn, &scoped_jar)?;
        staff.require(Permission::BanAccount, "Banlama yetkin yok.")?;
        let account = target_account(&conn, user_id)?;
        if account.role == UserRole::Owner {
            return Ok(true);
        }
        db::set_user_status(&conn, user_id, AccountStatus::Banned, None)?;
        // A banned account has nothing left to be signed into.
        db::delete_user_sessions_for_user(&conn, user_id)?;
        audit(&conn, &staff, "user_ban", user_id, "banned");
        Ok(false)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    return Ok(if refused? {
        back_to_users("Site sahibi banlanamaz.", true)
    } else {
        back_to_users("Hesap banlandı.", false)
    });
}

// POST /admin/users/unban
pub(in crate::server) async fn admin_user_unban(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Form(form): Form<UserActionForm>,
) -> Result<Response> {
    require_post_authorization(&jar, &headers, Some(peer), form.csrf.as_deref())?;
    let user_id = form.user_id;
    let scoped_jar = jar.clone();
    let pool = state.db.clone();

    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        let staff = acting_staff(&conn, &scoped_jar)?;
        staff.require(Permission::BanAccount, "Ban kaldırma yetkin yok.")?;
        target_account(&conn, user_id)?;
        db::set_user_status(&conn, user_id, AccountStatus::Active, None)?;
        audit(&conn, &staff, "user_unban", user_id, "ban lifted");
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    Ok(back_to_users("Ban kaldırıldı.", false))
}

#[cfg(test)]
/// The identity behind a request and the permissions that follow from it are
/// the whole gate on this section, so both are pinned here.
mod tests {
    use super::{
        acting_staff, validate_display_name, validate_username, PASSWORD_MAX_CHARS,
        PASSWORD_MIN_CHARS, USERS_PER_PAGE,
    };
    use crate::db;
    use crate::error::Result;
    use crate::middleware::AppState;
    use crate::roles::{Permission, UserRole};
    use axum_extra::extract::cookie::{Cookie, CookieJar};
    use chrono::Utc;
    use rusqlite::params;

    /// Create an account holding `role`, and return its id.
    fn seed_account(conn: &rusqlite::Connection, username: &str, role: UserRole) -> Result<i64> {
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let id = db::create_user(conn, username, username, &hash, None, "")?;
        db::set_user_role(conn, id, role)?;
        Ok(id)
    }

    /// A jar holding a live board session for `user_id`.
    fn session_jar(conn: &rusqlite::Connection, user_id: i64) -> Result<CookieJar> {
        let id = format!("sid-{user_id}");
        let expires_at = Utc::now().timestamp() + 3600;
        db::create_user_session(conn, &id, user_id, expires_at)?;
        let mut cookie = Cookie::new(crate::handlers::auth::USER_SESSION_COOKIE, id);
        cookie.set_path("/");
        Ok(CookieJar::from(cookie))
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the test asserts on the refusal, so a missing fixture database must fail the test immediately"
    )]
    /// A request with no session at all is refused rather than quietly treated
    /// as an anonymous operator.
    fn a_request_with_no_session_is_refused() {
        let state: AppState = crate::test_support::app_state();
        let conn = state.db.get().expect("test database");
        assert!(acting_staff(&conn, &CookieJar::new()).is_err());
    }

    #[test]
    /// An ordinary member's session does not open the section, whatever their
    /// karma says: the karma tiers grant nothing here.
    fn a_plain_member_cannot_reach_the_section() {
        let state = crate::test_support::app_state();
        let conn = state.db.get().expect("test database");
        let user_id = seed_account(&conn, "plainmember", UserRole::User).expect("seed");
        let jar = session_jar(&conn, user_id).expect("session");

        assert!(
            acting_staff(&conn, &jar).is_err(),
            "a member is not staff however trusted they are"
        );
    }

    #[test]
    /// Each staff role opens the section and carries exactly its own
    /// permissions, so reaching the page does not widen what someone may do.
    fn each_staff_role_opens_the_section_with_its_own_limits() {
        for (username, role, may_ban) in [
            ("rolemod", UserRole::Moderator, false),
            ("roleadmin", UserRole::Admin, true),
            ("roleowner", UserRole::Owner, true),
        ] {
            let state = crate::test_support::app_state();
            let conn = state.db.get().expect("test database");
            let user_id = seed_account(&conn, username, role).expect("seed");
            let jar = session_jar(&conn, user_id).expect("session");

            let staff = acting_staff(&conn, &jar).expect("a staff role opens the section");
            assert_eq!(staff.role, role);
            assert_eq!(staff.name, username);
            assert_eq!(staff.audit_id, user_id);
            assert!(staff.require(Permission::AccessAdminPanel, "no").is_ok());
            assert_eq!(
                staff.require(Permission::BanAccount, "no").is_ok(),
                may_ban,
                "{role:?} ban authority should be {may_ban}"
            );
            assert_eq!(
                staff.require(Permission::ResetAccountPassword, "no").is_ok(),
                role != UserRole::Moderator,
                "a moderator cannot replace a credential"
            );
        }
    }

    #[test]
    /// An operator session from the command line is the strongest identity and
    /// opens the section with the owner's authority.
    fn an_operator_session_is_treated_as_the_owner() {
        let state = crate::test_support::app_state();
        let conn = state.db.get().expect("test database");
        let hash = crate::utils::crypto::hash_password("hunter2").expect("hash");
        conn.execute(
            "INSERT INTO admin_users (id, username, password_hash) VALUES (1, 'rootop', ?1)",
            params![hash],
        )
        .expect("create operator");
        let expires_at = Utc::now().timestamp() + 3600;
        db::create_session(&conn, "op-sid", 1, expires_at).expect("session");
        let mut cookie = Cookie::new("chan_admin_session", "op-sid");
        cookie.set_path("/");

        let staff = acting_staff(&conn, &CookieJar::from(cookie)).expect("operator session");
        assert_eq!(staff.role, UserRole::Owner);
        assert_eq!(staff.name, "rootop");
        assert!(staff.require(Permission::RestoreDatabase, "no").is_ok());
    }

    #[test]
    /// The values an operator may type are held to the same rules registration
    /// holds a visitor to, so an operator cannot create a name the wizard would
    /// refuse.
    fn operator_side_values_are_held_to_the_registration_rules() {
        assert_eq!(validate_username("  Yeni-Ad  ").expect("valid"), "yeni-ad");
        assert!(validate_username("").is_err());
        assert!(validate_username("bir iki").is_err());
        assert!(validate_username(&"a".repeat(21)).is_err());
        assert_eq!(validate_display_name("  Anonim  ").expect("valid"), "Anonim");
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name(&"a".repeat(41)).is_err());
    }

    #[test]
    /// The credential bounds the handler enforces are the documented ones.
    fn credential_bounds_are_pinned() {
        assert_eq!(PASSWORD_MIN_CHARS, 6);
        assert_eq!(PASSWORD_MAX_CHARS, 256);
        assert_eq!(USERS_PER_PAGE, 25);
    }
}
