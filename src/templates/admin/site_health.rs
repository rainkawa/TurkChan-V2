//! Runtime health and dependency diagnostics for the admin panel.

use super::{escape_html, AdminDetectionStatus, AdminPanelViewModel};
use std::fmt::Write as _;

/// Renders the complete site-health section.
pub(super) fn render(view: &AdminPanelViewModel<'_>) -> String {
    let open_attr = if view.open_section == Some("site-health") {
        " open"
    } else {
        ""
    };
    let health = &view.site_health;
    let rows = render_health_rows(view);
    let dependency_rows = render_dependency_summary(view);
    let tor_rows = render_tor_diagnostics(view);
    let recent_jobs = render_recent_jobs_panel();
    let diagnostics = escape_html(health.diagnostics_text);
    format!(
        r##"<section class="admin-section admin-section-collapsible" id="site-health">
<details class="admin-dropdown" data-admin-dropdown-key="site-health"{open_attr}>
<summary><span>// site sağlığı</span></summary>
<div class="admin-dropdown-content admin-site-health" data-admin-health-jobs-url="/admin/site-health/jobs">
  <div class="admin-health-grid">{rows}</div>
  <noscript><p class="admin-copy">Canlı görev ayrıntıları JavaScript gerektirir. Sayaçları güncellemek için bu sayfayı yenile.</p></noscript>
  {recent_jobs}
  <div class="admin-subsection admin-subsection-tight admin-health-tor" id="tor-status">
    <div class="admin-card-header">
      <h3>// Tor tanılamaları</h3>
      <p>Çalışma zamanındaki onion servis durumu ve güvenli yapılandırma sinyalleri.</p>
    </div>
    <div class="admin-health-grid">{tor_rows}</div>
  </div>
  <div class="admin-subsection admin-subsection-tight admin-health-dependencies">
    <div class="admin-card-header">
      <h3>// isteğe bağlı bağımlılık özeti</h3>
      <p>Kısa başlangıç algılama sonuçları. Ayrıntılar tam medya araçları panelinde.</p>
    </div>
    <div class="admin-health-grid">{dependency_rows}</div>
    <p class="admin-copy admin-copy-spaced">
      <a class="admin-button-link" href="#media-settings" data-open-admin-section="media-settings">medya panelini aç</a>
    </p>
  </div>
  <details class="admin-diagnostics-details" data-admin-diagnostics>
    <summary>tanılamaları kopyala</summary>
    <div class="admin-diagnostics-panel" role="dialog" aria-modal="false" aria-labelledby="admin-diagnostics-title">
      <div class="admin-diagnostics-header">
        <h3 id="admin-diagnostics-title">// tanılamalar</h3>
        <div class="admin-diagnostics-actions">
          <button type="button" data-admin-diagnostics-copy hidden>Kopyala</button>
          <button type="button" data-admin-diagnostics-close hidden>kapat</button>
        </div>
      </div>
      <pre class="admin-diagnostics-text" data-admin-diagnostics-text>{diagnostics}</pre>
    </div>
  </details>
</div>
</details>
</section>"##,
    )
}

/// Renders the primary server, database, storage, and job health rows.
fn render_health_rows(view: &AdminPanelViewModel<'_>) -> String {
    let health = &view.site_health;
    let mut rows = String::new();
    for (label, value) in [
        ("Sunucu durumu", health.server_status),
        ("TurkChan version", health.rustchan_version),
        ("Veritabanı şeması", health.database_schema_status),
        (
            "Veritabanı bütünlük durumu",
            health.database_integrity_status,
        ),
        ("Son başarılı yedek", health.last_successful_backup),
        ("Sıradaki planlanmış yedek", health.next_scheduled_backup),
        ("Disk usage for rustchan-data/", health.data_dir_usage),
        ("Yükleme dizini boyutu", health.upload_dir_size),
    ] {
        append_health_row(&mut rows, label, value);
    }
    append_health_row(
        &mut rows,
        "Yedek depolama dizini",
        &crate::config::backups_dir().display().to_string(),
    );
    append_job_rows(&mut rows, view);
    rows
}

/// Appends live job-count rows to the health summary.
fn append_job_rows(rows: &mut String, view: &AdminPanelViewModel<'_>) {
    let health = &view.site_health;
    append_health_job_row(
        rows,
        "Çalışan görevler",
        &health.running_jobs.to_string(),
        "running_jobs",
        view.csrf_token,
    );
    append_health_job_row(
        rows,
        "Kuyruktaki görevler",
        &health.queued_jobs.to_string(),
        "queued_jobs",
        view.csrf_token,
    );
    append_health_job_row(
        rows,
        "Tamamlanan görevler",
        &health.recent_completed_jobs.to_string(),
        "recent_completed_jobs",
        view.csrf_token,
    );
    append_health_job_row(
        rows,
        "Başarısız görevler",
        &health.failed_jobs.to_string(),
        "failed_jobs",
        view.csrf_token,
    );
    append_health_job_row(
        rows,
        "Yedekleme görevleri",
        health.backup_jobs,
        "backup_jobs",
        view.csrf_token,
    );
    append_health_job_row(
        rows,
        "Geri yükleme görevleri",
        health.restore_jobs,
        "restore_jobs",
        view.csrf_token,
    );
}

/// Appends one escaped label-value health row.
fn append_health_row(out: &mut String, label: &str, value: &str) {
    let _ = write!(
        out,
        r#"<div class="admin-health-row"><span>{label}</span><strong>{value}</strong></div>"#,
        label = escape_html(label),
        value = escape_html(value),
    );
}

/// Appends a job-count row with the controls appropriate to its category.
fn append_health_job_row(out: &mut String, label: &str, value: &str, key: &str, csrf_token: &str) {
    if key == "failed_jobs" {
        let disabled_attr = if value == "0" {
            r#" disabled aria-disabled="true""#
        } else {
            ""
        };
        let _ = write!(
            out,
            r#"<div class="admin-health-row admin-health-row-actions"><button type="button" class="admin-health-inspect-button admin-health-count-button" data-admin-health-toggle="failed" aria-expanded="false" aria-controls="admin-health-job-panel-failed" disabled><span>{label} (<strong data-admin-health-job="{key}">{value}</strong>)</span></button><form method="POST" action="/admin/site-health/jobs/dismiss" class="admin-health-dismiss-form"><input type="hidden" name="_csrf" value="{csrf}"><button type="submit" data-admin-health-failed-dismiss{disabled_attr}>sayacı sıfırla</button></form></div>"#,
            label = escape_html(label),
            key = escape_html(key),
            value = escape_html(value),
            csrf = escape_html(csrf_token),
            disabled_attr = disabled_attr,
        );
        return;
    }
    if matches!(key, "failed_jobs" | "recent_completed_jobs") {
        let target = if key == "failed_jobs" {
            "failed"
        } else {
            "completed"
        };
        let _ = write!(
            out,
            r#"<div class="admin-health-row"><button type="button" class="admin-health-inspect-button admin-health-count-button" data-admin-health-toggle="{target}" aria-expanded="false" aria-controls="admin-health-job-panel-{target}" disabled><span>{label} (<strong data-admin-health-job="{key}">{value}</strong>)</span></button></div>"#,
            label = escape_html(label),
            key = escape_html(key),
            target = escape_html(target),
            value = escape_html(value),
        );
        return;
    }
    let _ = write!(
        out,
        r#"<div class="admin-health-row"><span>{label}</span><strong data-admin-health-job="{key}">{value}</strong></div>"#,
        label = escape_html(label),
        key = escape_html(key),
        value = escape_html(value),
    );
}

/// Renders the initially hidden recent-job detail panels.
fn render_recent_jobs_panel() -> String {
    r#"<div class="admin-health-job-details" data-admin-health-job-details hidden inert aria-hidden="true">
  <section id="admin-health-job-panel-failed" data-admin-health-job-panel="failed" hidden inert aria-hidden="true">
    <div class="admin-health-job-details-header">
      <h3>// son başarısız görevler</h3>
      <button type="button" data-admin-health-close>kapat</button>
    </div>
    <div class="admin-health-job-list" data-admin-health-job-list="failed"></div>
  </section>
  <section id="admin-health-job-panel-completed" data-admin-health-job-panel="completed" hidden inert aria-hidden="true">
    <div class="admin-health-job-details-header">
      <h3>// yakın zamanda tamamlanan görevler</h3>
      <button type="button" data-admin-health-close>kapat</button>
    </div>
    <div class="admin-health-job-list" data-admin-health-job-list="completed"></div>
  </section>
</div>"#
        .to_owned()
}

/// Renders detected-state rows for optional media dependencies.
fn render_dependency_summary(view: &AdminPanelViewModel<'_>) -> String {
    let dependencies = view.site_health.dependency_summary;
    let mut rows = String::new();
    for (label, status) in [
        ("ffmpeg", dependencies.ffmpeg),
        ("ffprobe", dependencies.ffprobe),
        ("WebP desteği", dependencies.webp),
        ("VP9 desteği", dependencies.vp9),
        ("Opus desteği", dependencies.opus),
    ] {
        append_health_row(&mut rows, label, detection_label(status));
    }
    rows
}

/// Renders the safe Tor runtime and configuration diagnostics.
fn render_tor_diagnostics(view: &AdminPanelViewModel<'_>) -> String {
    let health = &view.site_health;
    let mut rows = String::new();
    for (label, value) in [
        ("Tor desteği", health.tor_status),
        (
            "Onion erişilebilirliği",
            health.tor_onion_address.unwrap_or("mevcut değil"),
        ),
        ("Onion servisi", health.tor_service_status),
        ("Erişim modu", health.tor_mode),
        ("Çalışma zamanı yapılandırması", health.tor_config_summary),
        ("Durum ayrıntısı", health.tor_detail),
    ] {
        append_health_row(&mut rows, label, value);
    }
    rows
}

/// Converts a dependency detection state to display text.
const fn detection_label(status: AdminDetectionStatus) -> &'static str {
    match status {
        AdminDetectionStatus::Detected => "bulundu",
        AdminDetectionStatus::Missing => "eksik",
    }
}
