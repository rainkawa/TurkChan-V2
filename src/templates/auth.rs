//! Registration and sign-in screens.
//!
//! Both pages are built from the same layout and the same design tokens as the
//! rest of the site, so they read as part of the board rather than as a bolted
//! on login box. The registration form is a single document with three
//! `<fieldset>` steps: JavaScript reveals one step at a time, and without
//! JavaScript every step is simply visible in order, which keeps the flow
//! usable for a visitor with scripting disabled.

use crate::templates::{base_layout_with_preferences, static_asset_url};
use crate::utils::sanitize::escape_html;

use super::UserPreferences;

/// Label of the free-text name field on the registration wizard.
///
/// Every surface that shows this field reads it from here, so relabelling it
/// later from the administration panel is a single-site change rather than a
/// search across the templates and the handlers.
pub const DISPLAY_NAME_FIELD_LABEL: &str = "Görünen Ad";

/// Label of the sign-in form's user-name field.
pub const USERNAME_FIELD_LABEL: &str = "Kullanıcı Adı";

/// Label of the wizard's first step heading.
pub const STEP_DISPLAY_NAME_TITLE: &str = "Görünen Ad";

/// Label of the wizard's second step heading.
pub const STEP_USERNAME_TITLE: &str = "Kullanıcı Adı";

/// Label of the wizard's third step heading.
pub const STEP_PASSWORD_TITLE: &str = "Parola";

/// Number of steps in the registration wizard.
const REGISTER_STEPS: u32 = 3;

/// Longest accepted display name, mirrored by the `maxlength` attribute.
const DISPLAY_NAME_MAX_CHARS: usize = 40;

/// Longest accepted username, mirrored by the `maxlength` attribute.
const USERNAME_MAX_CHARS: usize = 20;

/// Longest accepted profile description, mirrored by the `maxlength` attribute.
const BIO_MAX_CHARS: usize = 280;

/// Shortest accepted password, mirrored by the `minlength` attribute.
const PASSWORD_MIN_CHARS: usize = 6;

/// Largest accepted avatar upload, in MiB, mirrored by the on-page hint.
const AVATAR_MAX_MIB: u32 = 2;

/// Script tag for the wizard enhancement, omitted when the file is absent.
fn auth_script_tag() -> String {
    format!(
        r#"<script src="{}" defer></script>"#,
        escape_html(&static_asset_url("/static/auth.js"))
    )
}

/// Render the sign-in screen.
///
/// `username` is pre-filled so a failed attempt does not force a retype.
/// `error` carries a user-facing failure message; `return_to` is a path the
/// visitor is sent back to after a successful sign-in.
#[must_use]
pub fn login_page(
    username: &str,
    csrf_token: &str,
    error: Option<&str>,
    return_to: &str,
) -> String {
    let error_html = error.map_or_else(String::new, |message| {
        format!(
            r#"<p class="auth-error" role="alert">{}</p>"#,
            escape_html(message)
        )
    });
    let return_to_field = format!(
        r#"<input type="hidden" name="return_to" value="{}">"#,
        escape_html(return_to)
    );

    let body = format!(
        r#"<div class="page-box auth-page">
<h1 class="auth-title">Giriş Yap</h1>
<p class="auth-lead">Devam etmek için hesabınla giriş yap.</p>
{error_html}
<form class="auth-form" method="POST" action="/login">
<input type="hidden" name="_csrf" value="{csrf}">
{return_to_field}
<label class="auth-label" for="auth-username">{username_label}</label>
<input class="auth-input" type="text" id="auth-username" name="username" value="{username}" autocomplete="username" maxlength="{username_max}" required autofocus>
<label class="auth-label" for="auth-password">Parola</label>
<input class="auth-input" type="password" id="auth-password" name="password" autocomplete="current-password" required>
<button class="btn auth-submit" type="submit">Giriş Yap</button>
</form>
<p class="auth-switch">Hesabın yok mu? <a href="/register">Kayıt Ol</a></p>
</div>
{auth_script_tag}"#,
        error_html = error_html,
        csrf = escape_html(csrf_token),
        return_to_field = return_to_field,
        username_label = escape_html(USERNAME_FIELD_LABEL),
        username_max = USERNAME_MAX_CHARS,
        username = escape_html(username),
        auth_script_tag = auth_script_tag(),
    );

    base_layout_with_preferences(
        "Giriş Yap",
        None,
        &body,
        csrf_token,
        &[],
        None,
        None,
        false,
        "/login",
        UserPreferences::default(),
    )
}

/// Values echoed back into the wizard after a rejected submission.
#[derive(Debug, Default)]
pub struct RegisterDraft {
    /// Display name the visitor typed.
    pub display_name: String,
    /// Username the visitor typed.
    pub username: String,
    /// Short description the visitor typed for their profile.
    pub bio: String,
    /// Whether the chosen username was still free, when it was probed.
    pub username_available: Option<bool>,
}

/// Render the registration wizard.
///
/// `step` re-opens the wizard on the step that failed so a visitor who mistyped
/// their password does not start over from the display name.
#[must_use]
pub fn register_page(
    csrf_token: &str,
    step: u32,
    draft: &RegisterDraft,
    error: Option<&str>,
) -> String {
    let step = step.clamp(1, REGISTER_STEPS);
    let error_html = error.map_or_else(String::new, |message| {
        format!(
            r#"<p class="auth-error" role="alert">{}</p>"#,
            escape_html(message)
        )
    });
    let username_status = match draft.username_available {
        Some(true) => r#"<p class="auth-ok" id="auth-username-status" role="status">Bu kullanıcı adı alınmış değil.</p>"#,
        Some(false) => r#"<p class="auth-error" id="auth-username-status" role="alert">Bu kullanıcı adı zaten alınmış.</p>"#,
        None => r#"<p class="auth-hint" id="auth-username-status" role="status"></p>"#,
    };

    let body = format!(
        r#"<div class="page-box auth-page auth-register-page">
<h1 class="auth-title">Kayıt Ol</h1>
<p class="auth-lead">Sadece bir görünen ad, bir kullanıcı adı ve bir parola. Gerçek adın, e-posta adresin ya da telefon numaran istenmez.</p>
<ol class="auth-steps">
<li class="auth-step-marker" data-auth-step-marker="1"><span class="auth-step-number">1</span> {title_1}</li>
<li class="auth-step-marker" data-auth-step-marker="2"><span class="auth-step-number">2</span> {title_2}</li>
<li class="auth-step-marker" data-auth-step-marker="3"><span class="auth-step-number">3</span> {title_3}</li>
</ol>
{error_html}
<form class="auth-form auth-wizard" id="auth-wizard" method="POST" action="/register" enctype="multipart/form-data" data-auth-start-step="{step}">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="step" id="auth-step-field" value="{step}">

<fieldset class="auth-step" data-auth-panel="1">
<legend class="auth-step-legend">{title_1}</legend>
<p class="auth-hint">Boardlarda gönderilerin yanında görünecek isim. Gerçek adın olmak zorunda değil.</p>
<label class="auth-label" for="auth-display-name">{display_label}</label>
<input class="auth-input" type="text" id="auth-display-name" name="display_name" value="{display_name}" maxlength="{display_max}" autocomplete="nickname" required>
<button class="btn auth-next" type="button" data-auth-next="2">İleri</button>
</fieldset>

<fieldset class="auth-step" data-auth-panel="2">
<legend class="auth-step-legend">{title_2}</legend>
<p class="auth-hint">Giriş yaparken kullanacağın benzersiz ad. Daha önce alınmışsa uyarı verilir.</p>
<label class="auth-label" for="auth-username">{username_label}</label>
<input class="auth-input" type="text" id="auth-username" name="username" value="{username}" maxlength="{username_max}" autocomplete="username" required>
{username_status}
<label class="auth-label" for="auth-avatar">Profil Resmi <span class="auth-optional">(isteğe bağlı)</span></label>
<input class="auth-input auth-file" type="file" id="auth-avatar" name="avatar" accept="image/png,image/jpeg,image/gif,image/webp,image/bmp,image/tiff">
<p class="auth-hint">Yüklemezsen varsayılan avatar kullanılır. En fazla {avatar_max} MiB.</p>
<label class="auth-label" for="auth-bio">Bio <span class="auth-optional">(isteğe bağlı)</span></label>
<textarea class="auth-input auth-textarea" id="auth-bio" name="bio" rows="3" maxlength="{bio_max}">{bio}</textarea>
<p class="auth-hint">Profilinde görünecek kısa bir açıklama. Gerçek ad, e-posta veya telefon yazma.</p>
<button class="btn auth-back" type="button" data-auth-back="1">Geri</button>
<button class="btn auth-next" type="button" data-auth-next="3">İleri</button>
</fieldset>

<fieldset class="auth-step" data-auth-panel="3">
<legend class="auth-step-legend">{title_3}</legend>
<p class="auth-hint">En az {password_min} karakter. İki kez yazmalısın.</p>
<label class="auth-label" for="auth-password">Parola</label>
<input class="auth-input" type="password" id="auth-password" name="password" minlength="{password_min}" autocomplete="new-password" required>
<label class="auth-label" for="auth-password-confirm">Parola Tekrar</label>
<input class="auth-input" type="password" id="auth-password-confirm" name="password_confirm" minlength="{password_min}" autocomplete="new-password" required>
<button class="btn auth-back" type="button" data-auth-back="2">Geri</button>
<button class="btn auth-submit" type="submit">Kayıt Ol</button>
</fieldset>
</form>
<p class="auth-switch">Zaten hesabın var mı? <a href="/login">Giriş Yap</a></p>
</div>
{auth_script_tag}"#,
        step = step,
        title_1 = escape_html(STEP_DISPLAY_NAME_TITLE),
        title_2 = escape_html(STEP_USERNAME_TITLE),
        title_3 = escape_html(STEP_PASSWORD_TITLE),
        error_html = error_html,
        username_status = username_status,
        csrf = escape_html(csrf_token),
        display_label = escape_html(DISPLAY_NAME_FIELD_LABEL),
        username_label = escape_html(USERNAME_FIELD_LABEL),
        display_max = DISPLAY_NAME_MAX_CHARS,
        username_max = USERNAME_MAX_CHARS,
        bio_max = BIO_MAX_CHARS,
        password_min = PASSWORD_MIN_CHARS,
        avatar_max = AVATAR_MAX_MIB,
        display_name = escape_html(&draft.display_name),
        username = escape_html(&draft.username),
        bio = escape_html(&draft.bio),
        auth_script_tag = auth_script_tag(),
    );

    base_layout_with_preferences(
        "Kayıt Ol",
        None,
        &body,
        csrf_token,
        &[],
        None,
        None,
        false,
        "/register",
        UserPreferences::default(),
    )
}

/// Render the confirmation shown on the home page after registration.
#[must_use]
pub fn registration_notice(display_name: &str) -> String {
    format!(
        r#"<p class="index-account-notice" role="status">Kaydın tamamlandı. Hoş geldin, {display_name}.</p>"#,
        display_name = escape_html(display_name),
    )
}

/// The signed-in identity rendered in the header account menu.
#[derive(Debug, Clone)]
pub struct AccountMenu {
    /// Name shown to other visitors.
    pub display_name: String,
    /// Unique login name.
    pub username: String,
    /// Whether this identity may also open the administration panel.
    pub is_admin: bool,
}

/// Return the single letter an account is shown as when it has no picture.
///
/// The chosen display name leads, because that is what a visitor reads
/// elsewhere on the site; the unique username is the fallback when the display
/// name has no letter in it at all.
#[must_use]
pub fn account_initial(display_name: &str, username: &str) -> String {
    display_name
        .chars()
        .find(|c| c.is_alphanumeric())
        .or_else(|| username.chars().find(|c| c.is_ascii_alphanumeric()))
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_owned())
}

/// Render the header account menu, or nothing when nobody is signed in.
///
/// "Profili Gör" opens the account's public profile. The two entries after it
/// stay inert: they are shown so the menu shape is settled, and only the
/// profile, the administration panel, and the sign-out control do anything yet.
#[must_use]
pub fn account_menu_html(account: Option<&AccountMenu>, csrf_token: &str) -> String {
    let Some(account) = account else {
        return String::new();
    };
    let initial = account_initial(&account.display_name, &account.username);
    let admin_item = if account.is_admin {
        r#"<a class="account-menu-item" href="/admin/panel">Admin Panel</a>"#
    } else {
        ""
    };
    // The account's public profile is the only profile entry that exists so
    // far; editing the account and its settings stay inert.
    let profile_item = format!(
        r#"<a class="account-menu-item" href="/u/{username}">Profili Gör</a>"#,
        username = escape_html(&account.username),
    );

    format!(
        r#"<details class="account-menu" id="account-menu">
<summary class="account-menu-button" aria-label="Hesap menüsünü aç" aria-controls="account-menu-panel"><span class="account-avatar" aria-hidden="true">{initial}</span></summary>
<div class="account-menu-panel" id="account-menu-panel">
<p class="account-menu-identity"><span class="account-menu-name">{display_name}</span><span class="account-menu-handle">@{username}</span></p>
{profile_item}
<span class="account-menu-item is-disabled" aria-disabled="true">Profili Düzenle</span>
<span class="account-menu-item is-disabled" aria-disabled="true">Ayarlar</span>
{admin_item}
<form class="account-menu-form" method="POST" action="/logout">
<input type="hidden" name="_csrf" value="{csrf}">
<button class="account-menu-item account-menu-logout" type="submit">Çıkış yap</button>
</form>
</div>
</details>"#,
        initial = escape_html(&initial),
        display_name = escape_html(&account.display_name),
        username = escape_html(&account.username),
        profile_item = profile_item,
        admin_item = admin_item,
        csrf = escape_html(csrf_token),
    )
}
