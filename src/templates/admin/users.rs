//! The administration panel's account-management section.
//!
//! This is the one place an operator changes another account: its names, its
//! credential, its staff role, and whether it may act at all. Each form names
//! the single permission it needs, so the section reads as the list of things
//! a role is actually for rather than a wall of controls.

use crate::models::{Pagination, User};
use crate::roles::{AccountStatus, Permission, RoleBadge, UserRole, MAX_SUSPEND_SECS};
use crate::templates::{base_layout, escape_html, render_pagination, urlencoding_simple};
use chrono::TimeZone as _;
use std::fmt::Write as _;

/// One account as the section shows it.
///
/// The password hash is deliberately absent: the section can rename an account
/// and replace its credential, but it never reads one.
#[derive(Debug)]
pub struct AdminUserRow {
    /// The account being listed.
    pub account: User,
    /// The badge shown for the account.
    pub badge: RoleBadge,
    /// The moderation state in force right now.
    pub status: AccountStatus,
    /// Second the current suspension ends, when one is in force.
    pub suspended_until: Option<i64>,
}

impl AdminUserRow {
    /// Prepare one listing row for the given moment.
    #[must_use]
    pub fn new(account: User, now: i64) -> Self {
        let status = account.effective_status(now);
        let badge = account.badge(now);
        let suspended_until = account.suspended_until;
        Self {
            account,
            badge,
            status,
            suspended_until,
        }
    }
}

/// Everything the section renders.
#[derive(Debug)]
pub struct AdminUsersView<'a> {
    /// Accounts on this page, already filtered and paginated.
    pub rows: &'a [AdminUserRow],
    /// Page metadata for the listing.
    pub pagination: &'a Pagination,
    /// The search term in force, echoed back into the field.
    pub search: &'a str,
    /// Message left by a previous action, and whether it is a failure.
    pub flash: Option<&'a (String, bool)>,
    /// Form token every form on the page carries.
    pub csrf_token: &'a str,
    /// What the operator acting on this page is allowed to do.
    pub acting_role: UserRole,
    /// Board chips for the shared layout.
    pub boards: &'a [crate::models::Board],
    /// Visitor-selected theme.
    pub current_theme: Option<&'a str>,
}

impl AdminUsersView<'_> {
    /// Whether the operator may perform `permission` on this page.
    #[must_use]
    pub fn allows(&self, permission: Permission) -> bool {
        self.acting_role.has(permission)
    }
}

/// Render the badge an account is shown with.
///
/// The colour is carried by an inline custom property rather than a class per
/// colour, so adding a badge is one entry in the role table and nothing else.
#[must_use]
pub fn role_badge_html(badge: RoleBadge) -> String {
    format!(
        r#"<span class="role-badge role-badge-{slug}" style="--role-color:{color}" title="{label}">{label}</span>"#,
        slug = badge_slug(badge),
        color = badge.color(),
        label = escape_html(badge.label()),
    )
}

/// The class-name fragment for a badge.
fn badge_slug(badge: RoleBadge) -> &'static str {
    match badge {
        RoleBadge::Banned => "banned",
        RoleBadge::Suspended => "suspended",
        RoleBadge::Owner => "owner",
        RoleBadge::Admin => "admin",
        RoleBadge::Moderator => "moderator",
        RoleBadge::God => "god",
        RoleBadge::Legend => "legend",
        RoleBadge::Angel => "angel",
        RoleBadge::Verified => "verified",
        RoleBadge::User => "user",
    }
}

/// Human-readable state of an account, with the moment a suspension ends.
fn status_label(row: &AdminUserRow) -> String {
    match row.status {
        AccountStatus::Banned => "Banlı".to_owned(),
        AccountStatus::Suspended => match row.suspended_until {
            Some(until) => format!("Askıda — {} bitişinde kalkar", fmt_until(until)),
            None => "Askıda".to_owned(),
        },
        AccountStatus::Active => "Aktif".to_owned(),
    }
}

/// Format a Unix second as a date the operator can read.
fn fmt_until(until: i64) -> String {
    match chrono::Local.timestamp_opt(until, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%d/%m/%Y %H:%M").to_string(),
        _ => "bilinmiyor".to_owned(),
    }
}

/// The role options an operator may hand out, filtered by what they may do.
///
/// An operator can never see the ownership option unless they own the site, so
/// the form cannot offer a choice the server would only refuse.
fn role_options(acting: UserRole, current: UserRole) -> String {
    let mut html = String::new();
    for role in UserRole::ALL {
        let grantable = role == UserRole::Owner || acting == UserRole::Owner;
        if !grantable {
            continue;
        }
        let selected = if role == current { " selected" } else { "" };
        let _ = write!(
            html,
            r#"<option value="{value}"{selected}>{label}</option>"#,
            value = role.as_str(),
            selected = selected,
            label = escape_html(role.label()),
        );
    }
    html
}

/// The form that changes an account's two names.
fn rename_form(row: &AdminUserRow, csrf: &str) -> String {
    let account = &row.account;
    format!(
        r#"<form method="POST" action="/admin/users/rename" class="admin-user-form">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="user_id" value="{id}">
<label>İsim<input type="text" name="display_name" maxlength="40" value="{display_name}" required></label>
<label>Kullanıcı adı<input type="text" name="username" maxlength="20" value="{username}" required></label>
<button type="submit">İsimleri Kaydet</button>
</form>"#,
        csrf = csrf,
        id = account.id,
        display_name = escape_html(&account.display_name),
        username = escape_html(&account.username),
    )
}

/// The form that replaces an account's credential.
///
/// The field is a password input and is never echoed back, so the value only
/// exists in the request that carried it.
fn password_form(row: &AdminUserRow, csrf: &str) -> String {
    format!(
        r#"<form method="POST" action="/admin/users/password" class="admin-user-form">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="user_id" value="{id}">
<label>Yeni parola<input type="password" name="password" minlength="6" maxlength="256" autocomplete="new-password" required></label>
<button type="submit">Parolayı Değiştir</button>
</form>"#,
        csrf = csrf,
        id = row.account.id,
    )
}

/// The form that changes an account's staff role.
fn role_form(view: &AdminUsersView<'_>, row: &AdminUserRow, csrf: &str) -> String {
    format!(
        r#"<form method="POST" action="/admin/users/role" class="admin-user-form">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="user_id" value="{id}">
<label>Rol<select name="role">{options}</select></label>
<button type="submit">Rolü Ata</button>
</form>"#,
        csrf = csrf,
        id = row.account.id,
        options = role_options(view.acting_role, row.account.role),
    )
}

/// The form that suspends an account for a while.
fn suspend_form(row: &AdminUserRow, csrf: &str) -> String {
    format!(
        r#"<form method="POST" action="/admin/users/suspend" class="admin-user-form">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="user_id" value="{id}">
<label>Askıya alma (saat)<input type="number" name="hours" min="1" max="720" value="24" required></label>
<button type="submit">Askıya Al</button>
</form>"#,
        csrf = csrf,
        id = row.account.id,
    )
}

/// A small form that only names its target: lifting a suspension, or banning.
///
/// A banned account offers the way back and no suspension, because the two
/// states are separate and a ban is not a suspension that has run out.
fn state_form(row: &AdminUserRow, csrf: &str) -> String {
    let banned = row.status == AccountStatus::Banned;
    let (action, label) = if banned {
        ("/admin/users/unban", "Bani Kaldır")
    } else {
        ("/admin/users/ban", "Banla")
    };
    format!(
        r#"<form method="POST" action="{action}" class="admin-user-form">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="user_id" value="{id}">
<button type="submit">{label}</button>
</form>"#,
        action = action,
        label = label,
        csrf = csrf,
        id = row.account.id,
    )
}

/// Build the per-account control panel shown in a row.
///
/// Each form is offered only when the acting role carries the permission it
/// exercises, so the page itself never shows a control the server would refuse.
fn render_row_controls(view: &AdminUsersView<'_>, row: &AdminUserRow) -> String {
    let csrf = escape_html(view.csrf_token);
    let mut parts: Vec<String> = Vec::new();
    if view.allows(Permission::RenameAccount) {
        parts.push(rename_form(row, &csrf));
    }
    if view.allows(Permission::ResetAccountPassword) {
        parts.push(password_form(row, &csrf));
    }
    if view.allows(Permission::AssignRoles) {
        parts.push(role_form(view, row, &csrf));
    }
    if view.allows(Permission::SuspendAccount) {
        match row.status {
            AccountStatus::Active => parts.push(suspend_form(row, &csrf)),
            AccountStatus::Suspended => parts.push(lift_form(row, &csrf)),
            AccountStatus::Banned => {}
        }
    }
    if view.allows(Permission::BanAccount) {
        parts.push(state_form(row, &csrf));
    }
    format!(
        "<details class=\"admin-user-controls\"><summary>İşlemler</summary>{}</details>",
        parts.concat()
    )
}

/// The form that ends a running suspension early.
fn lift_form(row: &AdminUserRow, csrf: &str) -> String {
    format!(
        r#"<form method="POST" action="/admin/users/lift" class="admin-user-form">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="user_id" value="{id}">
<button type="submit">Askıyı Kaldır</button>
</form>"#,
        csrf = csrf,
        id = row.account.id,
    )
}

/// Render the complete account-management section.
#[must_use]
pub fn admin_users_page(view: &AdminUsersView<'_>) -> String {
    let mut rows = String::new();
    if view.rows.is_empty() {
        rows.push_str(
            r#"<tr><td colspan="6" class="admin-users-empty">bu aramayla eşleşen hesap yok</td></tr>"#,
        );
    }
    for row in view.rows {
        let account = &row.account;
        let _ = write!(
            rows,
            r#"<tr>
<td><a href="/u/{username}"><strong>{display_name}</strong></a><br><span class="admin-user-handle">@{username}</span></td>
<td>{badge}</td>
<td>{status}</td>
<td>{karma}</td>
<td>{controls}</td>
<td><a href="/u/{username}">profil</a></td>
</tr>"#,
            username = escape_html(&account.username),
            display_name = escape_html(&account.display_name),
            badge = role_badge_html(row.badge),
            status = escape_html(&status_label(row)),
            karma = account.karma,
            controls = render_row_controls(view, row),
        );
    }

    let search_value = escape_html(view.search);
    let flash_html = view.flash.map_or_else(String::new, |(message, is_error)| {
        if *is_error {
            format!(
                r#"<p class="admin-flash admin-flash-error" role="alert">{}</p>"#,
                escape_html(message)
            )
        } else {
            format!(
                r#"<p class="admin-flash" role="status">{}</p>"#,
                escape_html(message)
            )
        }
    });
    let base_url = if view.search.is_empty() {
        "/admin/users".to_owned()
    } else {
        format!("/admin/users?q={}", urlencoding_simple(view.search))
    };
    let pagination = render_pagination(view.pagination, &base_url);
    let body = format!(
        r#"<div class="admin-panel admin-users">
{flash}
<div class="admin-panel-header">
  <div class="admin-panel-heading">
    <h1>[ kullanıcılar ]</h1>
    <p class="admin-panel-lead">Hesapların isimlerini, parolasını, rolünü ve erişimini yönet. Yetkin: <strong>{acting}</strong></p>
  </div>
  <a class="admin-panel-back" href="/admin/panel">panele dön</a>
</div>

<form method="GET" action="/admin/users" class="admin-users-search">
  <input type="search" name="q" value="{search}" placeholder="isim veya kullanıcı adı" aria-label="Hesap ara">
  <button type="submit">ara</button>
</form>

<div class="admin-table-wrap">
<table class="admin-users-table">
<thead>
  <tr><th>hesap</th><th>rol</th><th>durum</th><th>karma</th><th>işlemler</th><th></th></tr>
</thead>
<tbody>{rows}</tbody>
</table>
</div>
{pagination}
<p class="admin-users-hint">Askıya alma en fazla {max_days} gün sürer; daha uzun bir engel ban olarak kaydedilir.</p>
</div>"#,
        flash = flash_html,
        acting = escape_html(view.acting_role.label()),
        search = search_value,
        rows = rows,
        pagination = pagination,
        max_days = MAX_SUSPEND_SECS / 86_400,
    );

    base_layout(
        "kullanıcılar — yönetici",
        None,
        &body,
        view.csrf_token,
        view.boards,
        view.current_theme,
        None,
        false,
        "/admin/users",
    )
}

#[cfg(test)]
/// The section is the only place an operator edits an account, so what it
/// offers and what it refuses are pinned here.
mod tests {
    use super::{admin_users_page, role_badge_html, AdminUserRow, AdminUsersView};
    use crate::models::{Pagination, User};
    use crate::roles::{AccountStatus, Permission, RoleBadge, UserRole};

    /// An account with no staff role and no state on it.
    fn account() -> User {
        User {
            id: 7,
            username: "anon".to_owned(),
            display_name: "Anonim".to_owned(),
            password_hash: "hash".to_owned(),
            avatar_file: None,
            bio: "selam".to_owned(),
            karma: 3,
            role: UserRole::User,
            status: AccountStatus::Active,
            suspended_until: None,
            created_at: 1_700_000_000,
        }
    }

    /// The page as an ordinary moderator sees it.
    fn moderator_view(rows: &[AdminUserRow]) -> AdminUsersView<'_> {
        AdminUsersView {
            rows,
            pagination: &Pagination::new(1, 25, 1),
            search: "",
            flash: None,
            csrf_token: "csrf",
            acting_role: UserRole::Moderator,
            boards: &[],
            current_theme: None,
        }
    }

    #[test]
    /// A badge is one element carrying its own colour, and the label is
    /// escaped on the way out.
    fn a_badge_carries_its_colour_and_label() {
        let html = role_badge_html(RoleBadge::Legend);
        assert!(html.contains("role-badge-legend"), "got {html}");
        assert!(html.contains("--role-color:#3d8bd4"), "got {html}");
        assert!(html.contains(">Legend</span>"), "got {html}");
    }

    #[test]
    /// A moderator sees the tools their role is for and nothing more: they
    /// rename and suspend, and the role, password, and ban controls are simply
    /// not on the page.
    fn a_moderator_is_offered_only_their_own_tools() {
        let row = AdminUserRow::new(account(), 0);
        let view = moderator_view(std::slice::from_ref(&row));
        let html = admin_users_page(&view);

        assert!(html.contains(r#"action="/admin/users/rename""#), "got {html}");
        assert!(html.contains(r#"action="/admin/users/suspend""#));
        assert!(!html.contains(r#"action="/admin/users/role""#), "a moderator cannot hand out roles");
        assert!(!html.contains(r#"action="/admin/users/password""#), "a moderator cannot reset a password");
        assert!(!html.contains(r#"action="/admin/users/ban""#), "a moderator cannot ban");
        assert!(!view.allows(Permission::AssignRoles));
    }

    #[test]
    /// An administrator gets the role and password tools, and is still refused
    /// the ownership option because only the owner may hand that out.
    fn an_admin_gets_roles_and_passwords_but_not_ownership() {
        let row = AdminUserRow::new(account(), 0);
        let mut view = moderator_view(std::slice::from_ref(&row));
        view.acting_role = UserRole::Admin;
        let html = admin_users_page(&view);

        assert!(html.contains(r#"action="/admin/users/role""#));
        assert!(html.contains(r#"action="/admin/users/password""#));
        assert!(html.contains(r#"action="/admin/users/ban""#));
        assert!(
            !html.contains(r#"<option value="owner""#),
            "an administrator must not be able to hand out ownership"
        );
        assert!(html.contains(r#"<option value="admin""#));
    }

    #[test]
    /// The owner sees every control, including the one that grants ownership.
    fn the_owner_sees_every_control() {
        let row = AdminUserRow::new(account(), 0);
        let mut view = moderator_view(std::slice::from_ref(&row));
        view.acting_role = UserRole::Owner;
        let html = admin_users_page(&view);

        for action in ["rename", "password", "role", "suspend", "ban"] {
            assert!(
                html.contains(&format!(r#"action="/admin/users/{action}""#)),
                "the owner should be offered {action}, got {html}"
            );
        }
        assert!(html.contains(r#"<option value="owner""#));
    }

    #[test]
    /// A state that is in force is stated in words next to the account, not
    /// left for the reader to infer from the badge colour.
    fn a_suspended_account_says_when_its_suspension_ends() {
        let mut suspended = account();
        suspended.status = AccountStatus::Suspended;
        suspended.suspended_until = Some(1_700_000_000);
        let row = AdminUserRow::new(suspended, 1_699_999_999);
        let html = admin_users_page(&moderator_view(std::slice::from_ref(&row)));

        assert!(html.contains("Askıda — "), "got {html}");
        assert!(html.contains("role-badge-suspended"), "got {html}");
        // A running suspension offers the way back, and not another one.
        assert!(html.contains(r#"action="/admin/users/lift""#));
        assert!(!html.contains(r#"action="/admin/users/suspend""#));
    }

    #[test]
    /// A ban cannot also be lifted as a suspension, and offers the way back
    /// instead.
    fn a_banned_account_offers_the_way_back_and_nothing_else() {
        let mut banned = account();
        banned.status = AccountStatus::Banned;
        let row = AdminUserRow::new(banned, 0);
        let mut view = moderator_view(std::slice::from_ref(&row));
        view.acting_role = UserRole::Owner;
        let html = admin_users_page(&view);

        assert!(html.contains("Banlı"), "got {html}");
        assert!(html.contains(r#"action="/admin/users/unban""#));
        assert!(!html.contains(r#"action="/admin/users/suspend""#));
    }

    #[test]
    /// The message an action left behind is shown on the page it redirects to,
    /// and a failure is marked as one.
    fn a_flash_from_the_previous_action_is_shown() {
        let row = AdminUserRow::new(account(), 0);
        let mut view = moderator_view(std::slice::from_ref(&row));
        let done = ("Hesap banlandı.".to_owned(), false);
        view.flash = Some(&done);
        assert!(admin_users_page(&view).contains("Hesap banlandı."));

        let failed = ("Site sahibi banlanamaz.".to_owned(), true);
        view.flash = Some(&failed);
        let html = admin_users_page(&view);
        assert!(html.contains("role=\"alert\""), "got {html}");
        assert!(html.contains("Site sahibi banlanamaz."));
    }

    #[test]
    /// The listing says so when a search matched nothing, rather than showing
    /// an empty table with no explanation.
    fn an_empty_listing_says_so() {
        let view = moderator_view(&[]);
        let html = admin_users_page(&view);
        assert!(html.contains("bu aramayla eşleşen hesap yok"), "got {html}");
    }
}
