//! Registration, sign-in, and account settings screens.
//!
//! All of them are built from the same layout and the same design tokens as the
//! rest of the site, so they read as part of the board rather than as a bolted
//! on login box. The registration form is a single document with three
//! `<fieldset>` steps: JavaScript reveals one step at a time, and without
//! JavaScript every step is simply visible in order, which keeps the flow
//! usable for a visitor with scripting disabled. The account menu that the
//! shared header carries is rendered here too, and its "Profili Düzenle" entry
//! opens the settings screen that renames an account, replaces its picture, and
//! changes its password.

use crate::models::Board;
use crate::templates::{base_layout_with_account, base_layout_with_preferences, static_asset_url};
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

/// Longest accepted password, mirrored by the `maxlength` attribute.
const PASSWORD_MAX_CHARS: usize = 256;

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
/// "Profili Gör" opens the account's public profile and "Profili Düzenle"
/// opens the settings screen that renames the account, replaces its picture,
/// and changes its password. The administration panel entry and the sign-out
/// control sit after those two.
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
<a class="account-menu-item" href="/account/edit">Profili Düzenle</a>
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

/// The saved account the settings screen is built from.
#[derive(Debug)]
pub struct AccountSettings {
    /// Name shown on posts, pre-filled into the form.
    pub display_name: String,
    /// Login name, pre-filled into the form and shown in the profile hint.
    pub username: String,
    /// Row id, used to preview the stored avatar.
    pub user_id: i64,
    /// Whether a picture has been uploaded for this account.
    pub has_avatar: bool,
    /// Whether the password form is offered for this identity.
    ///
    /// An operator browses under an administrator name whose credential lives
    /// in `admin_users`, not in this row, so the section is replaced by a note
    /// rather than offering a change that would not take effect.
    pub can_change_password: bool,
}

/// The two tokens the settings screen carries.
///
/// The shared layout embeds the site-wide token in the header's own controls
/// (theme, board preferences, the not-a-bug report), while the settings forms
/// are scoped to the account CSRF cookie. The two cookies are separate on
/// purpose, so the screen has to carry both tokens rather than reuse one.
#[derive(Debug)]
pub struct AccountSettingsTokens {
    /// Token the shared layout embeds in the header controls.
    pub layout: String,
    /// Token the settings forms on this page carry.
    pub form: String,
}

/// The message shown above the settings forms.
#[derive(Debug)]
pub struct AccountSettingsNotice {
    /// Text shown to the visitor, empty when there is nothing to say.
    pub message: String,
    /// Whether the message reports a rejected submission.
    pub is_error: bool,
}

impl AccountSettingsNotice {
    /// A screen that says nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            message: String::new(),
            is_error: false,
        }
    }

    /// A confirmation that a change was stored.
    #[must_use]
    pub fn saved(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            is_error: false,
        }
    }

    /// A rejection that the forms are rendered again around.
    #[must_use]
    pub fn failed(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            is_error: true,
        }
    }
}

/// Render the account settings screen.
///
/// Everything an account can change about itself lives on this one page: the
/// profile picture, the display name, the username, and the password. The
/// picture travels with the profile form because it is one file and one
/// submit, while the password keeps its own form so a mistyped current
/// password never costs the visitor the rest of the form.
#[must_use]
pub fn account_settings_page(
    settings: &AccountSettings,
    boards: &[Board],
    current_theme: Option<&str>,
    preferences: UserPreferences,
    tokens: &AccountSettingsTokens,
    account_menu_html: &str,
    notice: &AccountSettingsNotice,
) -> String {
    let notice_html = if notice.message.is_empty() {
        String::new()
    } else if notice.is_error {
        format!(
            r#"<p class="account-notice is-error" role="alert">{}</p>"#,
            escape_html(&notice.message)
        )
    } else {
        format!(
            r#"<p class="account-notice" role="status">{}</p>"#,
            escape_html(&notice.message)
        )
    };

    // The stored picture and the drawn initial are both rendered the way the
    // profile page renders them, so the two never disagree about how an
    // account without a picture looks.
    let avatar = if settings.has_avatar {
        format!(
            r#"<img class="account-avatar-preview" src="/auth/avatar/{user_id}" width="96" height="96" alt="Mevcut profil resmi">"#,
            user_id = settings.user_id,
        )
    } else {
        format!(
            r#"<span class="account-avatar-preview account-avatar-preview-letter" role="img" aria-label="Profil resmin yok">{initial}</span>"#,
            initial = escape_html(&account_initial(
                &settings.display_name,
                &settings.username,
            )),
        )
    };

    let password_section = if settings.can_change_password {
        format!(
            r#"<form class="auth-form account-section" method="POST" action="/account/password">
<input type="hidden" name="_csrf" value="{csrf}">
<h2 class="account-section-title">Parola</h2>
<p class="auth-hint">Mevcut parolanı doğrulamak için önce onu isteyip sonra değiştiriyoruz.</p>
<label class="auth-label" for="account-current-password">Mevcut Parola</label>
<input class="auth-input" type="password" id="account-current-password" name="current_password" autocomplete="current-password" required>
<label class="auth-label" for="account-new-password">Yeni Parola</label>
<input class="auth-input" type="password" id="account-new-password" name="password" minlength="{password_min}" maxlength="{password_max}" autocomplete="new-password" required>
<label class="auth-label" for="account-new-password-confirm">Yeni Parola Tekrar</label>
<input class="auth-input" type="password" id="account-new-password-confirm" name="password_confirm" minlength="{password_min}" maxlength="{password_max}" autocomplete="new-password" required>
<button class="btn auth-submit" type="submit">Parolayı Değiştir</button>
</form>"#,
            csrf = escape_html(&tokens.form),
            password_min = PASSWORD_MIN_CHARS,
            password_max = PASSWORD_MAX_CHARS,
        )
    } else {
        r#"<p class="auth-hint account-section-hint">Parola değiştirme yalnızca kayıt olmuş üyeler için açıktır; yönetici parolası komut satırından yönetilir.</p>"#.to_owned()
    };

    let body = format!(
        r#"<div class="page-box auth-page account-page">
<h1 class="auth-title">Profili Düzenle</h1>
<p class="auth-lead">Profil resmin, görünen adın, kullanıcı adın ve parolan burada değişir. Gerçek adın, e-posta adresin ya da telefon numaran istenmez.</p>
{notice_html}

<form class="auth-form account-section" method="POST" action="/account/profile" enctype="multipart/form-data">
<input type="hidden" name="_csrf" value="{csrf}">
<h2 class="account-section-title">Profil</h2>
<div class="account-avatar-row">
{avatar}
<div class="account-avatar-fields">
<label class="auth-label" for="account-avatar">Profil Resmi</label>
<input class="auth-input auth-file" type="file" id="account-avatar" name="avatar" accept="image/png,image/jpeg,image/gif,image/webp,image/bmp,image/tiff">
<p class="auth-hint">Yeni resim seçmezsen mevcut resmin kalır. En fazla {avatar_max} MiB.</p>
</div>
</div>
<label class="auth-label" for="account-display-name">{display_label}</label>
<input class="auth-input" type="text" id="account-display-name" name="display_name" value="{display_name}" maxlength="{display_max}" autocomplete="nickname" required>
<label class="auth-label" for="account-username">{username_label}</label>
<input class="auth-input" type="text" id="account-username" name="username" value="{username}" maxlength="{username_max}" autocomplete="username" required>
<p class="auth-hint">Profil adresin bu addan türetilir: <code>/u/{username}</code>. Yalnızca harf, rakam, <code>_</code>, <code>-</code> ve <code>.</code> kullanabilirsin.</p>
<button class="btn auth-submit" type="submit">Kaydet</button>
</form>

{password_section}
<p class="auth-switch"><a href="/u/{profile_path}">Profiline dön</a></p>
</div>"#,
        notice_html = notice_html,
        csrf = escape_html(&tokens.form),
        avatar = avatar,
        password_section = password_section,
        display_label = escape_html(DISPLAY_NAME_FIELD_LABEL),
        username_label = escape_html(USERNAME_FIELD_LABEL),
        display_max = DISPLAY_NAME_MAX_CHARS,
        username_max = USERNAME_MAX_CHARS,
        avatar_max = AVATAR_MAX_MIB,
        display_name = escape_html(&settings.display_name),
        username = escape_html(&settings.username),
        profile_path = escape_html(&settings.username),
    );

    base_layout_with_account(
        "Profili Düzenle",
        None,
        &body,
        &tokens.layout,
        boards,
        current_theme,
        None,
        false,
        "/account/edit",
        preferences,
        account_menu_html,
    )
}
