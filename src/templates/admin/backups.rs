//! Full-site and per-board backup sections of the admin panel.

use super::{escape_html, format_file_size, render_board_backup_card, AdminPanelViewModel};
use std::fmt::Write as _;

/// Renders the complete backups tab of the admin panel.
pub(super) fn render(view: &AdminPanelViewModel<'_>) -> String {
    let backup_warning_html = view
        .backups
        .backup_warning
        .map_or_else(String::new, |message| {
            format!(
                r#"<div class="admin-flash flash-error admin-flash-spaced">{}</div>"#,
                escape_html(message)
            )
        });
    let full_backup_open_attr = if view.open_section == Some("full-backup-restore")
        || view.open_section == Some("board-backup-restore")
        || view
            .open_section
            .is_some_and(|section| section.starts_with("board-backup-"))
    {
        " open"
    } else {
        ""
    };
    let board_backup_open_attr = if view.open_section == Some("board-backup-restore")
        || view
            .open_section
            .is_some_and(|section| section.starts_with("board-backup-"))
    {
        " open"
    } else {
        ""
    };
    let mut board_backup_cards = String::new();
    for board in view.boards {
        board_backup_cards.push_str(&render_board_backup_card(
            board,
            view.csrf_token,
            view.open_section,
        ));
    }

    render_admin_backups_section(
        view.csrf_token,
        &backup_warning_html,
        view.backups.backup_status_line,
        view.backups.auto_full_backup_interval_hours,
        view.backups.auto_full_backup_copies_to_keep,
        view.backups.auto_full_backup_storage_mode,
        view.backups.auto_full_backup_split_zip_part_size_gib,
        &render_auto_full_backup_tor_option(view),
        &render_full_backup_create_tor_option(view),
        &render_full_backup_restore_upload_tor_option(view),
        full_backup_open_attr,
        board_backup_open_attr,
        &board_backup_cards,
        &render_full_backup_rows(view),
        &render_board_backup_rows(view),
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "each backup row keeps its related restore, download, and audit controls together"
)]
/// Renders saved full-backup rows and their available actions.
fn render_full_backup_rows(view: &AdminPanelViewModel<'_>) -> String {
    let mut full_backup_rows = String::new();
    if view.backups.full_backups.is_empty() {
        full_backup_rows
            .push_str(r#"<tr><td colspan="6" class="admin-table-empty">henüz yedek yok</td></tr>"#);
    }
    for bf in view.backups.full_backups {
        let size_fmt = format_file_size(bf.size_bytes.cast_signed());
        let status_html = if bf.verified {
            format!(
                r#"<span class="backup-verification-ok">{}</span>"#,
                escape_html(&bf.verification_note)
            )
        } else {
            format!(
                r#"<span class="backup-verification-error" title="{title}">doğrulama başarısız</span>"#,
                title = escape_html(&bf.verification_note)
            )
        };
        let mut board_options = String::new();
        for board in &bf.boards {
            let _ = write!(
                board_options,
                r#"<option value="{short}">/{short}/ — {name}</option>"#,
                short = escape_html(&board.short_name),
                name = escape_html(&board.name)
            );
        }
        let board_picker = if bf.boards.is_empty() {
            r#"<label>
        Board kısa adı
        <input type="text" name="board_short" maxlength="8" pattern="[A-Za-z0-9]{1,8}" required placeholder="tech">
      </label>"#.to_owned()
        } else {
            format!(
                r#"<label>
        Board
        <select name="board_short" required>
          <option value="">Bir board seç</option>
          {board_options}
        </select>
      </label>"#
            )
        };
        let board_help = if bf.boards.is_empty() {
            "Bu yedek, board dizinlemesinden önce oluşturulmuş. Board kısa adını tech veya b gibi elle gir."
        } else {
            "Doğrudan geri yüklemek veya yalnızca board paketi indirmek için bu yedekten bir board seç."
        };
        let indexed_boards_summary = if bf.boards.is_empty() {
            "boardlar dizinlenmemiş".to_owned()
        } else {
            format!("{} board dizinlendi", bf.boards.len())
        };
        let part_summary = if bf.part_count > 1 {
            format!("{} parça", bf.part_count)
        } else {
            "1 parça".to_owned()
        };
        let part_downloads = if bf.part_filenames.is_empty() {
            String::new()
        } else {
            let mut links = String::new();
            for part in &bf.part_filenames {
                let _ = write!(
                    links,
                    r#"<li><a href="/admin/backup/download/full/{backup_ref}?part={part}">{part}</a></li>"#,
                    backup_ref = escape_html(&bf.backup_ref),
                    part = escape_html(part)
                );
            }
            format!(
                r#"<p><strong>ZIP parçaları:</strong></p><ul class="backup-part-list">{links}</ul>"#
            )
        };
        let tor_backup_summary = if bf.contains_tor_hidden_service_keys {
            "Tor gizli servis anahtarları içeriyor"
        } else {
            "Tor gizli servis anahtarı yok"
        };
        let download_link = if bf.downloadable_archive {
            format!(
                r#"<a href="/admin/backup/download/full/{backup_ref}" class="backup-download-link" data-backup-label="full backup">&#8659; arşivi indir</a>"#,
                backup_ref = escape_html(&bf.backup_ref),
            )
        } else {
            String::new()
        };
        let restore_tor_keys_option = if bf.contains_tor_hidden_service_keys
            && view.backups.tor_hidden_service_key_backup_available
        {
            r#"<label class="admin-inline-checkbox backup-tor-option backup-tor-option-compact">
        <input type="checkbox" name="restore_tor_hidden_service_keys" value="1">
        <span>
          <strong>Tor anahtarlarını geri yükle</strong>
          <span class="admin-quick-help">Geçerli onion kimliğini bu yedekteki kimlikle değiştirir.</span>
        </span>
      </label>
      <p class="backup-extract-help backup-tor-warning">Bu anahtarlara sahip olan herkes bu onion servisini taklit edebilir.</p>"#.to_owned()
        } else {
            String::new()
        };
        let restore_confirm = if bf.contains_tor_hidden_service_keys
            && view.backups.tor_hidden_service_key_backup_available
        {
            format!(
                "UYARI: {fname} dosyasından geri yüklensin mi? Bu işlem canlı veritabanını ve tüm yüklemeleri üzerine yazar. Tor anahtarlarını da geri yüklersen diskteki geçerli onion kimliği değiştirilir. Geri alınamaz.",
                fname = bf.filename
            )
        } else {
            format!(
                "UYARI: {fname} dosyasından geri yüklensin mi? Bu işlem canlı veritabanını ve tüm yüklemeleri üzerine yazar. Geri alınamaz.",
                fname = bf.filename
            )
        };
        let _ = write!(
            full_backup_rows,
            r#"<tr>
<td class="backup-filename-cell">
  <div class="backup-filename">{backup_id}</div>
  <div class="backup-submeta">{scope} · {mode} · {part_summary}</div>
</td>
<td class="backup-meta-cell">{size}</td>
<td class="backup-meta-cell">{modified}</td>
<td class="backup-meta-cell">{mode}</td>
<td class="backup-status-cell">{status}</td>
<td class="backup-actions-cell">
  <div class="backup-actions-stack">
    <div class="backup-primary-actions">
      {download_link}
      <form method="POST" action="/admin/backup/restore-saved" class="backup-inline-form">
        <input type="hidden" name="_csrf" value="{csrf}">
        <input type="hidden" name="filename" value="{backup_ref}">
        <button type="submit" data-confirm="{restore_confirm}">&#8635; siteyi geri yükle</button>
        {restore_tor_keys_option}
      </form>
      <form method="POST" action="/admin/backup/delete" class="backup-inline-form">
        <input type="hidden" name="_csrf" value="{csrf}">
        <input type="hidden" name="kind" value="full">
        <input type="hidden" name="filename" value="{backup_ref}">
        <button type="submit" class="btn-danger" data-confirm="{backup_id} silinsin mi? Bu işlem geri alınamaz.">&#10005; sil</button>
      </form>
    </div>
    <details class="backup-extract-details">
      <summary>yedek ayrıntıları</summary>
      <div class="backup-extract-help">
        <p><strong>Yedek kimliği:</strong> <code>{backup_id}</code></p>
        <p><strong>Kapsam:</strong> {scope}</p>
        <p><strong>Mod:</strong> {mode}</p>
        <p><strong>ZIP parçaları:</strong> {part_summary}</p>
        {part_downloads}
        <p><strong>Manifest yolu:</strong> <code>{manifest_path}</code></p>
        <p><strong>Sunucu yolu:</strong> <code>{server_path}</code></p>
        <p><strong>Dahil edilen boardlar:</strong> {indexed_boards_summary}</p>
        <p><strong>Tor anahtarları:</strong> {tor_backup_summary}</p>
      </div>
    </details>
    <details class="backup-extract-details">
      <summary>tek board araçları</summary>
      <form method="POST" action="/admin/backup/extract-board" class="backup-extract-form">
        <input type="hidden" name="_csrf" value="{csrf}">
        <input type="hidden" name="filename" value="{backup_ref}">
        {board_picker}
        <p class="backup-extract-help">{board_help}</p>
        <div class="backup-extract-actions">
          <button type="submit" name="action" value="download">board zip’ini indir</button>
          <button type="submit" name="action" value="restore" class="btn-danger"
                  data-confirm="UYARI: {backup_id} içinden tek bir board geri yüklensin mi? Bu işlem yalnızca o board’u siler ve değiştirir. Devam edilsin mi?">&#8635; board’u geri yükle</button>
        </div>
      </form>
    </details>
  </div>
</td>
</tr>"#,
            backup_id = escape_html(&bf.backup_id),
            backup_ref = escape_html(&bf.backup_ref),
            scope = escape_html(&bf.scope),
            mode = escape_html(&bf.mode),
            part_summary = escape_html(&part_summary),
            part_downloads = part_downloads,
            indexed_boards_summary = escape_html(&indexed_boards_summary),
            tor_backup_summary = escape_html(tor_backup_summary),
            size = size_fmt,
            modified = escape_html(&bf.modified),
            status = status_html,
            csrf = escape_html(view.csrf_token),
            download_link = download_link,
            restore_tor_keys_option = restore_tor_keys_option,
            restore_confirm = escape_html(&restore_confirm),
            manifest_path = escape_html(&bf.manifest_path),
            server_path = escape_html(&bf.server_path),
            board_picker = board_picker,
            board_help = escape_html(board_help),
        );
    }
    full_backup_rows
}

/// Renders the Tor-key option for scheduled full backups when supported.
fn render_auto_full_backup_tor_option(view: &AdminPanelViewModel<'_>) -> String {
    if !view.backups.tor_hidden_service_key_backup_available {
        return String::new();
    }

    let checked = if view
        .backups
        .auto_full_backup_include_tor_hidden_service_keys
    {
        " checked"
    } else {
        ""
    };

    format!(
        r#"<label class="admin-inline-checkbox backup-tor-option">
      <input type="checkbox" name="auto_full_backup_include_tor_hidden_service_keys" value="1"{checked}>
      <span>
        <strong>Otomatik tam yedeklere Tor gizli servis anahtarlarını dahil et</strong>
        <span class="admin-quick-help">Geri yüklemeden sonra aynı .onion adresini korur. Bu anahtarlara sahip olan herkes bu onion servisini taklit edebilir.</span>
      </span>
    </label>"#
    )
}

/// Renders the Tor-key option for an on-demand full backup when supported.
fn render_full_backup_create_tor_option(view: &AdminPanelViewModel<'_>) -> String {
    if !view.backups.tor_hidden_service_key_backup_available {
        return String::new();
    }

    r#"<label class="admin-inline-checkbox backup-tor-option">
      <input type="checkbox" name="include_tor_hidden_service_keys" value="1">
      <span>
        <strong>Tor gizli servis anahtarlarını dahil et</strong>
        <span class="admin-quick-help">Geri yüklemeden sonra aynı .onion adresini korur. Bu anahtarlara sahip olan herkes bu onion servisini taklit edebilir.</span>
      </span>
    </label>"#.to_owned()
}

/// Renders the Tor-key restore option for uploaded full backups when supported.
fn render_full_backup_restore_upload_tor_option(view: &AdminPanelViewModel<'_>) -> String {
    if !view.backups.tor_hidden_service_key_backup_available {
        return String::new();
    }

    r#"<label class="admin-inline-checkbox backup-tor-option">
      <input type="checkbox" name="restore_tor_hidden_service_keys" value="1">
      <span>
        <strong>Tor gizli servis anahtarlarını geri yükle</strong>
        <span class="admin-quick-help">Yalnızca yüklenen yedek Tor gizli servis anahtarlarını içeriyorsa geçerlidir. Geçerli onion kimliğini yedekteki kimlikle değiştirir ve eski .onion adresini geri yükler.</span>
      </span>
    </label>
    <p class="backup-extract-help backup-tor-warning">Bu anahtarlara sahip olan herkes bu onion servisini taklit edebilir.</p>"#.to_owned()
}

/// Renders saved per-board backup rows and their available actions.
fn render_board_backup_rows(view: &AdminPanelViewModel<'_>) -> String {
    let mut board_backup_rows = String::new();
    if view.backups.board_backups.is_empty() {
        board_backup_rows.push_str(
            r#"<tr><td colspan="6" class="admin-table-empty">henüz board yedeği yok</td></tr>"#,
        );
    }
    for bf in view.backups.board_backups {
        let size_fmt = format_file_size(bf.size_bytes.cast_signed());
        let status_html = if bf.verified {
            format!(
                r#"<span class="backup-verification-ok">{}</span>"#,
                escape_html(&bf.verification_note)
            )
        } else {
            format!(
                r#"<span class="backup-verification-error" title="{title}">doğrulama başarısız</span>"#,
                title = escape_html(&bf.verification_note)
            )
        };
        let download_link = if bf.downloadable_archive {
            format!(
                r#"<a href="/admin/backup/download/board/{backup_ref}" class="backup-download-link" data-backup-label="board backup">&#8659; arşivi indir</a>"#,
                backup_ref = escape_html(&bf.backup_ref),
            )
        } else {
            String::new()
        };
        let _ = write!(
            board_backup_rows,
            r#"<tr>
<td class="backup-filename-cell">
  <div class="backup-filename">{backup_id}</div>
  <div class="backup-submeta">{mode}</div>
</td>
<td class="backup-meta-cell">{size}</td>
<td class="backup-meta-cell">{modified}</td>
<td class="backup-meta-cell">{mode}</td>
<td class="backup-status-cell">{status}</td>
<td class="backup-actions-cell">
  <div class="backup-actions-stack">
    <div class="backup-primary-actions">
      {download_link}
      <form method="POST" action="/admin/board/backup/restore-saved" class="backup-inline-form">
        <input type="hidden" name="_csrf" value="{csrf}">
        <input type="hidden" name="filename" value="{backup_ref}">
        <button type="submit" data-confirm="UYARI: {backup_id} içinden board geri yüklensin mi? Bu işlem o board’u siler ve değiştirir. Geri alınamaz.">&#8635; board’u geri yükle</button>
      </form>
      <form method="POST" action="/admin/backup/delete" class="backup-inline-form">
        <input type="hidden" name="_csrf" value="{csrf}">
        <input type="hidden" name="kind" value="board">
        <input type="hidden" name="filename" value="{backup_ref}">
        <button type="submit" class="btn-danger" data-confirm="{backup_id} silinsin mi? Bu işlem geri alınamaz.">&#10005; sil</button>
      </form>
    </div>
    <details class="backup-extract-details">
      <summary>yedek ayrıntıları</summary>
      <div class="backup-extract-help">
        <p><strong>Yedek kimliği:</strong> <code>{backup_id}</code></p>
        <p><strong>Kapsam:</strong> {scope}</p>
        <p><strong>Mod:</strong> {mode}</p>
        <p><strong>Manifest yolu:</strong> <code>{manifest_path}</code></p>
        <p><strong>Sunucu yolu:</strong> <code>{server_path}</code></p>
      </div>
    </details>
  </div>
</td>
</tr>"#,
            backup_id = escape_html(&bf.backup_id),
            backup_ref = escape_html(&bf.backup_ref),
            scope = escape_html(&bf.scope),
            mode = escape_html(&bf.mode),
            size = size_fmt,
            modified = escape_html(&bf.modified),
            status = status_html,
            csrf = escape_html(view.csrf_token),
            download_link = download_link,
            manifest_path = escape_html(&bf.manifest_path),
            server_path = escape_html(&bf.server_path),
        );
    }
    board_backup_rows
}

/// Renders supported split-archive sizes and selects the configured value.
fn split_zip_part_size_options(selected_gib: u64) -> String {
    let mut options = String::new();
    for value in [1, 2, 4, 8, 16, 32, 64] {
        let selected = if value == selected_gib {
            " selected"
        } else {
            ""
        };
        let _ = write!(
            options,
            r#"<option value="{value}"{selected}>{value} GiB</option>"#
        );
    }
    options
}

#[expect(
    clippy::too_many_lines,
    reason = "the backup section is one stable server-rendered HTML fragment"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the section interpolates independent pre-rendered backup controls"
)]
/// Renders the full-site and per-board backup management sections.
fn render_admin_backups_section(
    csrf_token: &str,
    backup_warning_html: &str,
    backup_status_line: &str,
    auto_full_backup_interval_hours: u64,
    auto_full_backup_copies_to_keep: u64,
    auto_full_backup_storage_mode: &str,
    auto_full_backup_split_zip_part_size_gib: u64,
    auto_full_backup_tor_option: &str,
    full_backup_create_tor_option: &str,
    full_backup_restore_upload_tor_option: &str,
    full_backup_open_attr: &str,
    board_backup_open_attr: &str,
    board_backup_cards: &str,
    full_backup_rows: &str,
    board_backup_rows: &str,
) -> String {
    let auto_directory_checked = if auto_full_backup_storage_mode == "split_zip" {
        ""
    } else {
        " checked"
    };
    let auto_split_zip_checked = if auto_full_backup_storage_mode == "split_zip" {
        " checked"
    } else {
        ""
    };
    let auto_part_options = split_zip_part_size_options(auto_full_backup_split_zip_part_size_gib);
    let manual_part_options = split_zip_part_size_options(4);
    format!(
        r#"<div class="admin-panel-backups" id="backups">
<section class="admin-section admin-section-collapsible" id="full-backup-restore">
<details class="admin-dropdown" data-admin-dropdown-key="full-backup-restore"{full_backup_open_attr}>
<summary><span>// tam site yedekleme &amp; geri yükleme</span></summary>
<div class="admin-dropdown-content">
<p class="admin-copy">Tam yedekler veritabanının tamamını ve yüklenen tüm dosyaları içerir. <strong>Sunucuya kaydet</strong>, sunucu dosya sisteminde <code>{effective_backup_directory}/&lt;backup_id&gt;/</code> altında bir Backup v4 klasörü oluşturur (aşağıda listelenir). <strong>Yerel dosyadan geri yükle</strong> bilgisayarından bir zip yükler. Kayıtlı tam yedekler, ayrı board yedekleri planlamadan tek bir board’u çıkarmak veya doğrudan geri yüklemek için de kullanılabilir.</p>
{backup_warning_html}
<p class="admin-copy"><strong>Yedek sağlığı:</strong> {backup_status_line}</p>
<div class="admin-subsection">
  <div class="admin-card-header"><h3>// yedek depolama dizini</h3></div>
  <p class="admin-copy">Geçerli dizin: <code>{effective_backup_directory}</code><br>Varsayılan dizin: <code>{default_backup_directory}</code></p>
  <form method="POST" action="/admin/backup/settings" class="admin-site-settings-form">
    <input type="hidden" name="_csrf" value="{csrf}">
    <label>Yedek dizini (sunucu dosya sisteminde mutlak yol)
      <input type="text" name="backup_directory" value="{effective_backup_directory}" required>
    </label>
    <button type="submit">yedek dizinini kaydet</button>
  </form>
  <p class="admin-meta-note">TurkChan yeniden başlatıldıktan sonra kayıtlı tüm yedeklere uygulanır. Mevcut yedekler taşınmaz; yalnızca etkin dizin listelenir. Mevcut varsayılan yedeklere dönmek için yukarıda gösterilen varsayılan dizini gir. Bağlı diskin ya da NAS’ın üzerinde ayrılmış bir dizin kullan; TurkChan özel izinler belirleyebilmeli ve dosyaları okuyabilmeli, yazabilmeli ve silebilmelidir. CHAN_BACKUP_DIRECTORY ortam değişkeni settings.toml değerine göre önceliklidir.</p>
</div>
<div class="admin-subsection">
  <div class="admin-card-header">
    <h3>// otomatik tam yedekler</h3>
    <p>Arka planda tam site anlık görüntüleri planla ve sunucunun kaç kayıtlı kopyayı saklayacağını belirle.</p>
  </div>
  <form method="POST" action="/admin/backup/settings" class="admin-site-settings-form full-backup-settings-form">
  <input type="hidden" name="_csrf" value="{csrf}">
  <div class="board-settings-grid admin-settings-grid">
    <label title="0 planlanmış tam yedekleri devre dışı bırakır.">
      Otomatik yedekler arasındaki saat
      <input type="number" name="auto_full_backup_interval_hours" value="{auto_full_backup_interval_hours}" min="0" max="8760">
    </label>
    <label title="Kayıtlı bir tam yedek tamamlandığında, bu sınırın ötesindeki en eski kayıtlı tam yedekler silinir.">
      Saklanacak tam yedek sayısı
      <input type="number" name="auto_full_backup_copies_to_keep" value="{auto_full_backup_copies_to_keep}" min="1" max="1000">
    </label>
  </div>
  <div class="backup-form-options full-backup-options">
  <fieldset class="backup-output-fieldset">
    <legend>Yedek çıktısı</legend>
    <label class="backup-output-option">
      <input type="radio" name="auto_full_backup_storage_mode" value="directory"{auto_directory_checked}>
      <span>
        <strong>Dizin</strong>
        <small>Sunucu yerelinde Backup v4 klasörü.</small>
      </span>
    </label>
    <label class="backup-output-option backup-output-option-split">
      <input type="radio" name="auto_full_backup_storage_mode" value="split_zip"{auto_split_zip_checked}>
      <span>
        <strong>Bölünmüş ZIP</strong>
        <small>Daha kolay aktarım için ZIP parçaları yazar.</small>
      </span>
      <span class="backup-output-select">
        <span>Parça boyutu</span>
        <select name="auto_full_backup_split_zip_part_size_gib">
          {auto_part_options}
        </select>
      </span>
    </label>
  </fieldset>
  {auto_full_backup_tor_option}
  </div>
  <div class="board-settings-actions">
    <button type="submit">otomatik yedekleme ayarlarını kaydet</button>
  </div>
  </form>
  <p class="admin-meta-note admin-meta-note-spaced">
    Otomatik tam yedekleri devre dışı bırakmak için saati <code>0</code> yap. Sunucuya tam yedek kaydetmek, otomatik çalıştırmalar dahil, saklama sınırının ötesindeki en eski kayıtlı tam yedekleri temizler.
  </p>
</div>
<div class="admin-subsection">
  <details class="backup-manual-details">
  <summary>Elle yedekleme</summary>
  <div class="backup-manual-content">
  <div class="full-backup-run-actions">
  <form method="POST" action="/admin/backup/create" id="full-backup-create-form" class="backup-action-form full-backup-action-form">
  <input type="hidden" name="_csrf" value="{csrf}">
  <fieldset class="backup-output-fieldset">
    <legend>Yedek çıktısı</legend>
    <label class="backup-output-option">
      <input type="radio" name="storage_mode" value="directory" checked>
      <span>
        <strong>Dizin</strong>
        <small>Sunucu yerelinde Backup v4 klasörü.</small>
      </span>
    </label>
    <label class="backup-output-option backup-output-option-split">
      <input type="radio" name="storage_mode" value="split_zip">
      <span>
        <strong>Bölünmüş ZIP</strong>
        <small>Daha kolay aktarım için ZIP parçaları yazar.</small>
      </span>
      <span class="backup-output-select">
        <span>Parça boyutu</span>
        <select name="split_zip_part_size_gib">
          {manual_part_options}
        </select>
      </span>
    </label>
  </fieldset>
  <button type="submit" id="full-backup-btn">&#128190; sunucuya kaydet</button>
  <div class="backup-form-options full-backup-options">
  {full_backup_create_tor_option}
  </div>
  </form>
  <form method="POST" action="/admin/restore" enctype="multipart/form-data" class="backup-restore-upload-form admin-file-inline-form full-backup-action-form" data-restore-label="full backup">
  <input type="hidden" name="_csrf" value="{csrf}">
  <label class="admin-quick-field admin-file-field">Yedek arşivi
    <input type="file" name="backup_file" accept=".zip" required class="admin-file-input">
    <span class="admin-quick-help">Tam site için bir zip yedeği yükle.</span>
  </label>
  <button type="submit" class="btn-danger"
          data-confirm="UYARI: Bu işlem veritabanını ve yüklenen tüm dosyaları üzerine yazar. Geri alınamaz. Devam edilsin mi?">&#8635; yerel dosyadan geri yükle</button>
  <div class="backup-form-options full-backup-options">
  {full_backup_restore_upload_tor_option}
  </div>
  </form>
  </div>
  </div>
  </details>
</div>
<div class="admin-subsection">
  <div class="admin-card-header">
    <h3>// kayıtlı tam yedekler</h3>
    <p>Kayıtlı herhangi bir tam site arşivinden indir, geri yükle, sil veya tek bir board çıkar.</p>
  </div>
  <div class="admin-table-wrap">
  <table class="admin-table backup-table">
  <thead><tr><th>yedek</th><th>boyut</th><th>oluşturma</th><th>mod</th><th>durum</th><th></th></tr></thead>
  <tbody>{full_backup_rows}</tbody>
  </table>
  </div>
</div>
<details class="backup-extract-details"{board_backup_open_attr}>
<summary>gelişmiş: board yedekleme ve geri yükleme</summary>
<p class="admin-copy">Board yedekleri tek bir board’u kapsar. Buradaki board bazlı araçları <code>{effective_backup_directory}/&lt;backup_id&gt;/</code> altında bir Backup v4 klasörü saklamak için ya da kayıtlı yedekleri geri yüklemek/silmek için kullan. <strong>Yerel dosyadan geri yükle</strong> bilgisayarından bir zip yükler.</p>
<div class="admin-subsection">
  <div class="admin-card-header">
    <h3>// board yedeği oluştur</h3>
    <p>Board’a özel yedekleme işlemlerini rutin board yönetiminden ayrı tut.</p>
  </div>
  <div class="admin-board-cards">{board_backup_cards}</div>
</div>
<div class="admin-subsection">
  <div class="admin-card-header">
    <h3>// yerel dosyadan geri yükle</h3>
    <p>Yalnızca tek bir board’u silip değiştirmek için bilgisayarından bir board yedeği yükle.</p>
  </div>
  <div class="admin-inline-actions admin-inline-actions-spaced">
  <form method="POST" action="/admin/board/restore" enctype="multipart/form-data" class="backup-restore-upload-form admin-file-inline-form" data-restore-label="board backup">
  <input type="hidden" name="_csrf" value="{csrf}">
  <label class="admin-quick-field admin-file-field">Board yedeği
    <input type="file" name="backup_file" accept=".zip,.json" required class="admin-file-input">
    <span class="admin-quick-help">Bir board zip’i ya da ham <code>board.json</code> manifesti yükle.</span>
  </label>
  <button type="submit" class="btn-danger"
          data-confirm="UYARI: Bu işlem board’u yedekten alıp değiştirir. Diğer boardlar etkilenmez. Devam edilsin mi?">&#8635; board’u yerel dosyadan geri yükle</button>
  </form>
  </div>
</div>
<div class="admin-subsection">
  <div class="admin-card-header">
    <h3>// kayıtlı board yedekleri</h3>
    <p>Board düzeyindeki yedekler genellikle yukarıdaki board kartlarından oluşturulur, ardından buradan indirilir, geri yüklenir veya silinir.</p>
  </div>
  <div class="admin-table-wrap">
  <table class="admin-table backup-table">
  <thead><tr><th>yedek</th><th>boyut</th><th>oluşturma</th><th>mod</th><th>durum</th><th></th></tr></thead>
  <tbody>{board_backup_rows}</tbody>
  </table>
  </div>
</div>
</details>
</div>
</details>
</section>
</div>"#,
        effective_backup_directory =
            escape_html(&crate::config::backups_dir().display().to_string()),
        default_backup_directory =
            escape_html(&crate::config::default_backups_dir().display().to_string()),
        csrf = escape_html(csrf_token),
        backup_warning_html = backup_warning_html,
        backup_status_line = backup_status_line,
        auto_full_backup_interval_hours = auto_full_backup_interval_hours,
        auto_full_backup_copies_to_keep = auto_full_backup_copies_to_keep,
        auto_directory_checked = auto_directory_checked,
        auto_split_zip_checked = auto_split_zip_checked,
        auto_part_options = auto_part_options,
        manual_part_options = manual_part_options,
        auto_full_backup_tor_option = auto_full_backup_tor_option,
        full_backup_create_tor_option = full_backup_create_tor_option,
        full_backup_restore_upload_tor_option = full_backup_restore_upload_tor_option,
        full_backup_open_attr = full_backup_open_attr,
        board_backup_open_attr = board_backup_open_attr,
        board_backup_cards = board_backup_cards,
        full_backup_rows = full_backup_rows,
        board_backup_rows = board_backup_rows,
    )
}
