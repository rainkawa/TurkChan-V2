//! Admin-panel shell, dashboard, and shared status components.

use super::{
    appearance, backups, base_layout, boards, control_center, escape_html, maintenance, moderation,
    site_health,
};
use super::{AdminPanelFlash, AdminPanelViewModel};

/// Renders the complete admin panel page.
pub(super) fn render(view: &AdminPanelViewModel<'_>) -> String {
    let flash_html = render_flash(view.flash);
    let section_index = render_admin_section_index();
    let overview_section = render_admin_overview_section(view);
    let site_settings_section = appearance::render_site_settings(view);
    let site_health_section = site_health::render(view);
    let boards_section = boards::render(view);
    let moderation_section = moderation::render(view);
    let appearance_section = appearance::render(view);
    let backups_section = backups::render(view);
    let maintenance_section = maintenance::render(view);

    let body = format!(
        r#"<div class="admin-panel">
{flash}
<div class="admin-panel-header">
  <div class="admin-panel-heading">
    <h1>[ yönetim paneli ]</h1>
    <p class="admin-panel-lead">Boardları, moderasyonu, temaları, yedekleri ve site ayarlarını tek yerden yönet.</p>
  </div>
  <form method="POST" action="/admin/logout" class="admin-panel-logout">
    <input type="hidden" name="_csrf" value="{csrf}">
    <button type="submit">çıkış yap</button>
  </form>
</div>

{section_index}
{overview_section}
{site_settings_section}
{site_health_section}
{boards_section}
{moderation_section}
{appearance_section}
{backups_section}
{maintenance_section}

<div id="backup-modal" class="compress-modal admin-modal-hidden" role="dialog" aria-modal="true" aria-labelledby="backup-modal-title" aria-hidden="true" hidden inert>
  <div class="compress-modal-box">
    <div class="compress-modal-title" id="backup-modal-title">&#128190; Yedek Oluşturuluyor…</div>
    <div class="compress-progress admin-progress-spaced" id="backup-progress-wrap">
      <div class="compress-progress-track"><div class="compress-progress-bar" id="backup-progress-bar"></div></div>
      <div class="compress-progress-text" id="backup-progress-text">Başlatılıyor…</div>
    </div>
    <div class="compress-done-actions admin-modal-hidden" id="backup-done-actions" hidden>
      <button class="compress-cancel-btn" data-action="close-backup-modal">&#10003; Bitti — yeniden yükle</button>
    </div>
  </div>
</div>"#,
        flash = flash_html,
        section_index = section_index,
        csrf = escape_html(view.csrf_token),
    );

    base_layout(
        "yönetim paneli",
        None,
        &body,
        view.csrf_token,
        view.boards,
        view.current_theme,
        Some(view.appearance.default_theme),
        false,
        "/admin/panel",
    )
}

/// Renders a success or error flash message when one is present.
fn render_flash(flash: Option<AdminPanelFlash<'_>>) -> String {
    flash.map_or_else(String::new, |flash| {
        let cls = if flash.is_error {
            "flash-error"
        } else {
            "flash-ok"
        };
        format!(
            r#"<div class="admin-flash {cls}">{msg}</div>"#,
            cls = cls,
            msg = escape_html(flash.message),
        )
    })
}

/// Renders links to each major admin-panel section.
const fn render_admin_section_index() -> &'static str {
    r##"<nav class="admin-section-index" aria-label="Yönetim paneli bölümleri">
  <span>git</span>
  <a href="#control-center">kontrol merkezi</a>
  <a href="#site-settings">site ayarları</a>
  <a href="#site-health">site sağlığı</a>
  <a href="#boards">boardlar</a>
  <a href="#moderation">moderasyon</a>
  <a href="#appearance">görünüm</a>
  <a href="#backups">yedekler</a>
  <a href="#maintenance">bakım</a>
</nav>"##
}

/// Renders the dashboard and live-log overview.
fn render_admin_overview_section(view: &AdminPanelViewModel<'_>) -> String {
    let dashboard = control_center::render(view);
    let live_log_open_attr = if view.open_section == Some("live-log") {
        " open"
    } else {
        ""
    };
    format!(
        r#"<div class="admin-panel-overview" id="overview">
{dashboard}
<section class="admin-section" id="live-log">
<details class="admin-dropdown" data-admin-dropdown-key="live-log"{live_log_open_attr}>
<summary>// canlı log</summary>
<div class="admin-dropdown-content">
<p class="admin-copy">
  <span id="admin-live-log-file">geçerli log</span> izleniyor. Her 2 saniyede güncellenir.
</p>
<p id="admin-live-log-status" class="admin-meta-note">JavaScript canlı güncellemeleri sağlar. Geçerli logun son kısmı aşağıda görünmeye devam eder.</p>
<p class="admin-copy admin-copy-spaced"><a href="/admin/log/live?bytes=65536">geçerli logun son kısmını aç (JSON)</a></p>
<div class="admin-inline-actions admin-inline-actions-spaced" data-admin-live-log-controls hidden>
  <button type="button" id="admin-live-log-refresh">şimdi yenile</button>
  <button type="button" id="admin-live-log-clear">temizle</button>
  <label class="admin-inline-toggle">
    <input type="checkbox" id="admin-live-log-autoscroll" checked> otomatik kaydırma
  </label>
</div>
<pre id="admin-live-log-output" class="admin-log-output">Canlı güncellemeler JavaScript kullanılabilir olduğunda başlar.</pre>
</div>
</details>
</section>
</div>"#,
    )
}
