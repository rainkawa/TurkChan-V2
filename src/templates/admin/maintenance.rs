//! Media-pipeline and database-maintenance sections of the admin panel.

use super::{escape_html, format_file_size, AdminPanelViewModel};
use std::fmt::Write as _;

/// Pre-rendered values interpolated into the maintenance section.
struct MaintenanceSectionView<'a> {
    /// CSRF token for state-changing forms.
    csrf_token: &'a str,
    /// Optional database-size warning banner.
    db_warn_banner: &'a str,
    /// Human-readable database size.
    db_size_str: &'a str,
    /// Optional Tor address details.
    tor_section: &'a str,
    /// Configured external-media process timeout.
    ffmpeg_timeout_secs: u64,
    /// Human-readable timeout help text.
    ffmpeg_timeout_help: &'a str,
    /// Whether automatic media pruning is enabled.
    media_auto_prune_enabled: bool,
    /// Numeric component of the active-media size threshold.
    media_max_active_content_size_value: u64,
    /// Unit component of the active-media size threshold.
    media_max_active_content_size_unit: &'a str,
    /// Pre-rendered media dependency cards.
    media_detection_cards: &'a str,
    /// `open` attribute for the media settings disclosure.
    media_settings_open_attr: &'a str,
    /// `open` attribute for the database maintenance disclosure.
    database_maintenance_open_attr: &'a str,
    /// Short setup-state label.
    setup_status: &'a str,
    /// Detailed setup-state explanation.
    setup_status_detail: &'a str,
    /// Warning displayed before reopening setup.
    setup_reopen_warning: &'a str,
    /// Optional form for closing a reopened setup wizard.
    setup_close_control: &'a str,
}

/// Renders the complete maintenance tab of the admin panel.
pub(super) fn render(view: &AdminPanelViewModel<'_>) -> String {
    let media_settings_open_attr = if view.open_section == Some("media-settings") {
        " open"
    } else {
        ""
    };
    let database_maintenance_open_attr = if view.open_section == Some("database-maintenance") {
        " open"
    } else {
        ""
    };
    let db_warn_banner = if view.maintenance.db_size_warning {
        format!(
            r#"<div class="admin-flash flash-error admin-flash-spaced">
&#9888; <strong>Veritabanı boyutu uyarısı:</strong> Veritabanı dosyası yapılandırılmış
uyarı eşiğini aştı ({size}). Sorgu performansının düşmesini önlemek için aşağıdan
<strong>VACUUM</strong> çalıştırmayı veya eski boardları arşivlemeyi düşün.
</div>"#,
            size = format_file_size(view.maintenance.db_size_bytes),
        )
    } else {
        String::new()
    };

    let tor_section = if view.tor_address.is_none() {
        String::new()
    } else {
        let mut addresses = String::new();
        if let Some(addr) = view.tor_address {
            let _ = write!(
                addresses,
                r#"<p class="admin-copy">Onion adresi: <a href="http://{addr}" target="_blank" rel="noreferrer">{addr}</a></p>"#,
                addr = escape_html(addr)
            );
        }
        addresses
    };
    let db_size_str = format_file_size(view.maintenance.db_size_bytes);
    let ffmpeg_timeout_help =
        crate::config::describe_timeout_secs(view.maintenance.ffmpeg_timeout_secs);
    let (media_max_value, media_max_unit) =
        media_size_input_parts(view.maintenance.media_max_active_content_size_bytes);
    let media_detection_cards = render_media_detection_cards(view);
    let (setup_status, setup_status_detail) = match view.maintenance.setup_status {
        super::AdminPanelSetupStatus::Reopened => (
            "yeniden açıldı",
            "Kurulum sihirbazı bir yönetici tarafından yeniden açıldı ve yalnızca doğrulanmış yöneticilere açıktır.",
        ),
        super::AdminPanelSetupStatus::Complete => (
            "tamamlandı",
            "Kurulum sihirbazı tamamlandı ve herkese açık kurulum rotaları engellendi.",
        ),
        super::AdminPanelSetupStatus::Available => (
            "mevcut",
            "Bu örnek hâlâ ilk çalıştırma kurulumunda görünüyor.",
        ),
        super::AdminPanelSetupStatus::Initialized => (
            "başlatıldı",
            "Bu örnekte kalıcı çalışma zamanı durumu mevcut, bu yüzden ilk çalıştırma kurulum rotaları engellendi.",
        ),
    };
    let setup_reopen_warning = "Kurulumu yeniden açmak canlı ayarları düzenlenebilir hale getirir. Mevcut yönetici kimlik bilgilerinin yerini almaz ve hâlâ doğrulanmış bir yönetici oturumu gerektirir.";
    let setup_close_control = if matches!(
        view.maintenance.setup_status,
        super::AdminPanelSetupStatus::Reopened
    ) {
        r#"<form method="POST" action="/admin/setup/close" class="admin-inline-actions">
    <input type="hidden" name="_csrf" value="{csrf}">
    <button type="submit"
            data-confirm="Canlı ayarları değiştirmeden kurulum sihirbazını kapat?">kurulum sihirbazını kapat</button>
  </form>"#
    } else {
        ""
    };
    let section_view = MaintenanceSectionView {
        csrf_token: view.csrf_token,
        db_warn_banner: &db_warn_banner,
        db_size_str: &db_size_str,
        tor_section: &tor_section,
        ffmpeg_timeout_secs: view.maintenance.ffmpeg_timeout_secs,
        ffmpeg_timeout_help: &ffmpeg_timeout_help,
        media_auto_prune_enabled: view.maintenance.media_auto_prune_enabled,
        media_max_active_content_size_value: media_max_value,
        media_max_active_content_size_unit: media_max_unit,
        media_detection_cards: &media_detection_cards,
        media_settings_open_attr,
        database_maintenance_open_attr,
        setup_status,
        setup_status_detail,
        setup_reopen_warning,
        setup_close_control,
    };
    render_admin_maintenance_section(&section_view)
}

/// Splits a byte threshold into an exact mebibyte or gibibyte input value.
const fn media_size_input_parts(bytes: u64) -> (u64, &'static str) {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    if bytes > 0 && bytes.is_multiple_of(GIB) {
        (bytes / GIB, "gib")
    } else {
        (bytes / MIB, "mib")
    }
}

/// Renders startup detection cards for media-processing capabilities.
fn render_media_detection_cards(view: &AdminPanelViewModel<'_>) -> String {
    let pdf_renderer = view
        .maintenance
        .media_detection
        .pdf_thumbnail_renderer
        .as_deref()
        .unwrap_or("none");
    let pdf_detail = if view
        .maintenance
        .media_detection
        .pdf_thumbnail_renderer
        .is_some()
    {
        format!("selected renderer: {pdf_renderer}")
    } else {
        "using built-in generic PDF placeholder thumbnail".to_owned()
    };

    let mut cards = String::new();
    for (label, ok, detail) in [
        (
            "ffmpeg",
            view.maintenance.media_detection.ffmpeg.is_detected(),
            "video küçük resimleri, ses dalgası işleri ve dönüştürme giriş noktası",
        ),
        (
            "ffprobe",
            view.maintenance.media_detection.ffprobe.is_detected(),
            "WebM codec inspection for uploads that need it",
        ),
        (
            "WebP encoder",
            view.maintenance.media_detection.webp_encoder.is_detected(),
            "resimden WebP’ye dönüştürme",
        ),
        (
            "VP9/WebM pipeline",
            view.maintenance.media_detection.vp9_pipeline.is_detected(),
            "MP4 to WebM transcoding with VP9 + Opus",
        ),
        (
            "PDF thumbnails",
            view.maintenance
                .media_detection
                .pdf_thumbnail_renderer
                .is_some(),
            &pdf_detail,
        ),
    ] {
        let _ = write!(
            cards,
            r#"<article class="admin-detection-card">
  <div class="admin-detection-card-header">
    <h3>{label}</h3>
    <span class="admin-detection-pill {pill_class}">{status}</span>
  </div>
  <p>{detail}</p>
</article>"#,
            label = escape_html(label),
            pill_class = if ok {
                "admin-detection-pill-ok"
            } else {
                "admin-detection-pill-missing"
            },
            status = if ok { "algılandı" } else { "eksik" },
            detail = escape_html(detail),
        );
    }
    cards
}

#[expect(
    clippy::too_many_lines,
    reason = "the maintenance controls form one stable server-rendered HTML fragment"
)]
/// Renders media settings, database tools, and setup controls.
fn render_admin_maintenance_section(view: &MaintenanceSectionView<'_>) -> String {
    format!(
        r#"<div class="admin-panel-maintenance" id="maintenance">
<section class="admin-section admin-section-collapsible" id="media-settings">
<details class="admin-dropdown" data-admin-dropdown-key="media-settings"{media_settings_open_attr}>
<summary><span>// medya ayarları</span></summary>
<div class="admin-dropdown-content">
<div class="admin-subsection admin-subsection-tight">
  <div class="admin-card-header">
    <h3>// medya hattı algılama</h3>
    <p>Başlangıçta ana harici medya araçları için yapılan kontroller.</p>
  </div>
  <div class="admin-detection-grid">{media_detection_cards}</div>
</div>
<form method="POST" action="/admin/media/settings" class="admin-site-settings-form">
  <input type="hidden" name="_csrf" value="{csrf}">
<div class="admin-subsection admin-subsection-tight">
  <div class="admin-card-header">
    <h3>// ffmpeg timeout</h3>
    <p>Yavaş bir video dönüştürme işlemini sonlandırmadan önce TurkChan’ın bekleyeceği süreyi ayarla.</p>
  </div>
<p class="admin-copy">
  TurkChan currently allows ffmpeg to run for <strong>{ffmpeg_timeout_help}</strong> before a long-running media job is killed.
  This primarily affects uploaded video re-encoding, especially slow MP4 to WebM/VP9 conversion.
</p>
  <div class="board-settings-grid admin-settings-grid">
    <label title="Yavaş sistemlerde ffmpeg video dönüştürme işleri için daha yüksek bir değer gerekebilir.">
      Video yeniden kodlama zaman aşımı (saniye)
      <input type="number" name="ffmpeg_timeout_secs" value="{ffmpeg_timeout_secs}" min="{ffmpeg_timeout_min}" max="{ffmpeg_timeout_max}" step="1" inputmode="numeric" class="admin-input-compact" required>
    </label>
  </div>
  <p class="admin-meta-note admin-meta-note-spaced">
    This controls how long TurkChan lets ffmpeg run while converting uploaded videos.
    Raspberry Pi gibi yavaş sistemler daha yüksek bir değer gerektirebilir.
    Donanım hızlandırma olmadan MP4’ten WebM/VP9’e kodlama özellikle yavaş olabilir.
    Videolar zaman aşımı nedeniyle dönüştürülemiyorsa bu değeri artır.
  </p>
</div>
<div class="admin-subsection admin-subsection-tight">
  <div class="admin-card-header">
    <h3>// medya temizleme</h3>
    <p>Etkin depolanan medya yapılandırılmış sınırı aştığında en eski tam boy gönderi medyalarını sil. Küçük resimler mümkün olduğunca korunur.</p>
  </div>
  <div class="board-settings-grid admin-settings-grid">
    <label title="Etkin medya sınırını ayarlanmamış bırakmak için 0 yap. Temizleme etkinken en az 1 MiB kullan.">
      En büyük etkin içerik veritabanı/medya boyutu
      <span class="admin-inline-control">
        <input type="number" name="media_max_active_content_size" value="{media_max_active_content_size}" min="0" step="1" inputmode="numeric" class="admin-input-compact">
        <select name="media_max_active_content_size_unit">
          <option value="mib"{media_max_unit_mib_selected}>MiB</option>
          <option value="gib"{media_max_unit_gib_selected}>GiB</option>
          <option value="bytes"{media_max_unit_bytes_selected}>bayt</option>
        </select>
      </span>
    </label>
  </div>
  <div class="board-settings-checks">
    <label class="admin-inline-checkbox" title="Etkin depolanan medya yapılandırılmış sınırı aştığında en eski tam boy gönderi medyalarını sil. Küçük resimler mümkün olduğunca korunur.">
      <input type="checkbox" name="media_auto_prune_enabled" value="1"{media_auto_prune_checked}>
      Otomatik etkin içerik temizlemeyi etkinleştir
    </label>
  </div>
</div>
<div class="board-settings-actions">
  <button type="submit">medya ayarlarını kaydet</button>
</div>
</form>
</div>
</details>
</section>

<section class="admin-section admin-section-collapsible" id="database-maintenance">
<details class="admin-dropdown" data-admin-dropdown-key="database-maintenance"{database_maintenance_open_attr}>
<summary><span>// veritabanı bakımı</span></summary>
<div class="admin-dropdown-content">
{db_warn_banner}<p class="admin-copy">
  Geçerli veritabanı boyutu: <strong>{db_size_str}</strong>.
  <strong>VACUUM</strong> çalıştırmak veritabanı dosyasını sıkıştırarak yeniden yazar ve toplu
  silmelerden (silinen konular, temizlenen gönderiler vb.) kalan boşluğu geri kazanır.
  Bu, büyük veritabanlarında birkaç saniye sürebilir ve kısa süre yazmaları engeller.
</p>
<p class="admin-copy admin-copy-spaced">
  Geri yükleme veya büyük silmelerden sonra veritabanı kontrollerini çalıştır. Onarımdan önce
  yedek al; onarım indeksleri ve arama verisini yeniden kurabilir, ancak gerçek dosya bozulmasını
  çözemeyebilir.
</p>
<div class="admin-inline-actions">
<form method="POST" action="/admin/db/check">
  <input type="hidden" name="_csrf" value="{csrf}">
  <button type="submit">&#x1F50E; veritabanı sağlığını denetle</button>
</form>
<form method="POST" action="/admin/vacuum">
  <input type="hidden" name="_csrf" value="{csrf}">
  <button type="submit"
          data-confirm="VACUUM çalıştırılsın mı? Yeniden kurarken veritabanı kısa süreyle engellenecek. Devam edilsin mi?">&#x1F9F9; VACUUM çalıştır</button>
</form>
</div>
<div class="admin-subsection admin-subsection-tight">
  <div class="admin-card-header">
    <h3>// kurulum durumu</h3>
    <p>İlk çalıştırma kurulum rotalarının durumu ve kontrollü bakım yeniden açma.</p>
  </div>
  <p class="admin-copy">
    Kurulum durumu: <strong>{setup_status}</strong>. {setup_status_detail}
  </p>
  <p class="admin-meta-note admin-meta-note-spaced">{setup_reopen_warning}</p>
  <form method="POST" action="/admin/setup/reopen" class="admin-inline-actions">
    <input type="hidden" name="_csrf" value="{csrf}">
    <button type="submit"
            data-confirm="Kurulum sihirbazı yeniden açılsın mı? Bu işlem canlı ayarları düzenler ve yalnızca yöneticilere açık kalır. Devam edilsin mi?">kurulum sihirbazını yeniden aç</button>
  </form>
  {setup_close_control}
</div>
</div>
</details>
</section>

{tor_section}
</div>"#,
        csrf = escape_html(view.csrf_token),
        db_warn_banner = view.db_warn_banner,
        db_size_str = view.db_size_str,
        ffmpeg_timeout_secs = view.ffmpeg_timeout_secs,
        media_auto_prune_checked = if view.media_auto_prune_enabled {
            " checked"
        } else {
            ""
        },
        media_max_active_content_size = view.media_max_active_content_size_value,
        media_max_unit_mib_selected = if view.media_max_active_content_size_unit == "mib" {
            " selected"
        } else {
            ""
        },
        media_max_unit_gib_selected = if view.media_max_active_content_size_unit == "gib" {
            " selected"
        } else {
            ""
        },
        media_max_unit_bytes_selected = if view.media_max_active_content_size_unit == "bytes" {
            " selected"
        } else {
            ""
        },
        ffmpeg_timeout_help = escape_html(view.ffmpeg_timeout_help),
        media_detection_cards = view.media_detection_cards,
        ffmpeg_timeout_min = crate::config::MIN_FFMPEG_TIMEOUT_SECS,
        ffmpeg_timeout_max = crate::config::MAX_FFMPEG_TIMEOUT_SECS,
        media_settings_open_attr = view.media_settings_open_attr,
        database_maintenance_open_attr = view.database_maintenance_open_attr,
        setup_status = escape_html(view.setup_status),
        setup_status_detail = escape_html(view.setup_status_detail),
        setup_reopen_warning = escape_html(view.setup_reopen_warning),
        setup_close_control = view
            .setup_close_control
            .replace("{csrf}", &escape_html(view.csrf_token)),
        tor_section = view.tor_section,
    )
}
