//! Report, appeal, ban, and word-filter sections of the admin panel.

use super::{escape_html, fmt_ts, AdminPanelViewModel};
use std::fmt::Write as _;

/// Renders the complete moderation tab of the admin panel.
pub(super) fn render(view: &AdminPanelViewModel<'_>) -> String {
    let report_count = view.moderation.reports.len();
    let appeal_count = view.moderation.appeals.len();
    let ban_count = view.moderation.bans.len();
    let filter_count = view.moderation.filters.len();
    let report_badge = if report_count > 0 {
        format!(r#" <span class="report-badge">{report_count}</span>"#)
    } else {
        String::new()
    };
    let appeal_badge = if appeal_count > 0 {
        format!(r#" <span class="report-badge">{appeal_count}</span>"#)
    } else {
        String::new()
    };
    let ban_badge = format!(r#" <span class="admin-count-badge">{ban_count}</span>"#);
    let filter_badge = format!(r#" <span class="admin-count-badge">{filter_count}</span>"#);
    let moderation_summary_counter = format!("Şikayet kutusu: [{report_count}]");

    render_admin_moderation_section(
        view.csrf_token,
        &render_report_rows(view),
        &render_appeal_rows(view.csrf_token, view.moderation.appeals),
        &render_ban_rows(view),
        &render_filter_rows(view),
        &report_badge,
        &appeal_badge,
        &ban_badge,
        &filter_badge,
        &moderation_summary_counter,
        view.open_section,
    )
}

/// Renders active-ban table rows.
fn render_ban_rows(view: &AdminPanelViewModel<'_>) -> String {
    let mut ban_rows = String::new();
    for ban in view.moderation.bans {
        let expires = ban
            .expires_at
            .map_or_else(|| "kalıcı".to_owned(), fmt_ts);
        let _ = write!(
            ban_rows,
            r#"<tr>
<td class="ip-hash">{}</td><td>{}</td><td>{}</td>
<td>
<form method="POST" action="/admin/ban/remove" style="display:inline">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="ban_id" value="{id}">
<button type="submit">kaldır</button>
</form>
</td>
</tr>"#,
            escape_html(ban.ip_hash.get(..16).unwrap_or(&ban.ip_hash)),
            escape_html(ban.reason.as_deref().unwrap_or("")),
            escape_html(&expires),
            csrf = escape_html(view.csrf_token),
            id = ban.id
        );
    }
    ban_rows
}

/// Renders word-filter table rows.
fn render_filter_rows(view: &AdminPanelViewModel<'_>) -> String {
    let mut filter_rows = String::new();
    for f in view.moderation.filters {
        let _ = write!(
            filter_rows,
            r#"<tr>
<td>{}</td><td>{}</td>
<td>
<form method="POST" action="/admin/filter/remove" style="display:inline">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="filter_id" value="{id}">
<button type="submit">sil</button>
</form>
</td>
</tr>"#,
            escape_html(&f.pattern),
            escape_html(&f.replacement),
            csrf = escape_html(view.csrf_token),
            id = f.id
        );
    }
    filter_rows
}

/// Renders open-report table rows.
fn render_report_rows(view: &AdminPanelViewModel<'_>) -> String {
    let mut report_rows = String::new();
    if view.moderation.reports.is_empty() {
        report_rows.push_str(
            r#"<tr><td colspan="6" style="color:var(--text-dim);text-align:center">açık şikayet yok</td></tr>"#,
        );
    }
    for rc in view.moderation.reports {
        let preview = escape_html(rc.post_preview.trim());
        let reason = escape_html(&rc.report.reason);
        let age = fmt_ts(rc.report.created_at);
        let user_info = rc.post_ip_hash.as_deref().map_or_else(
            || String::from(r#"<span style="color:var(--text-dim)">n/a</span>"#),
            |ip_hash| {
                let short = ip_hash.get(..16).unwrap_or(ip_hash);
                format!(
                    r#"<a href="/admin/ip/{ip_hash}" title="Karma IP geçmişini gör">{short}…</a>"#,
                    ip_hash = escape_html(ip_hash),
                    short = escape_html(short),
                )
            },
        );
        let _ = write!(
            report_rows,
            r#"<tr>
<td><a href="/{board}/thread/{tid}#p{pid}" title="gönderiyi gör">/{board}/ No.{pid}</a></td>
<td>{user_info}</td>
<td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{preview}">{preview}</td>
<td>{reason}</td>
<td style="white-space:nowrap;font-size:0.78rem">{age}</td>
<td style="white-space:nowrap">
  <form method="POST" action="/admin/report/resolve" style="display:inline">
    <input type="hidden" name="_csrf"      value="{csrf}">
    <input type="hidden" name="report_id"  value="{rid}">
    <button type="submit">&#10003; çöz</button>
  </form>
</td>
</tr>"#,
            board = escape_html(&rc.board_short),
            tid = rc.report.thread_id,
            pid = rc.report.post_id,
            user_info = user_info,
            preview = preview,
            reason = reason,
            age = escape_html(&age),
            csrf = escape_html(view.csrf_token),
            rid = rc.report.id
        );
    }
    report_rows
}

/// Renders pending ban-appeal table rows.
fn render_appeal_rows(csrf_token: &str, appeals: &[crate::models::BanAppeal]) -> String {
    let mut appeal_rows = String::new();
    if appeals.is_empty() {
        appeal_rows.push_str(
            r#"<tr><td colspan="4" style="color:var(--text-dim);text-align:center">açık itiraz yok</td></tr>"#,
        );
    }
    for a in appeals {
        let reason = escape_html(a.reason.trim());
        let age = fmt_ts(a.created_at);
        let ip_short = a.ip_hash.get(..16).unwrap_or(&a.ip_hash);
        let ip_short = escape_html(ip_short);
        let _ = write!(
            appeal_rows,
            r#"<tr>
<td style="font-size:0.78rem;font-family:monospace">{ip_short}…</td>
<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{reason}">{reason}</td>
<td style="white-space:nowrap;font-size:0.78rem">{age}</td>
<td style="white-space:nowrap">
  <form method="POST" action="/admin/appeal/dismiss" style="display:inline">
    <input type="hidden" name="_csrf"      value="{csrf}">
    <input type="hidden" name="appeal_id"  value="{aid}">
    <button type="submit">✕ reddet</button>
  </form>
  <form method="POST" action="/admin/appeal/accept" style="display:inline;margin-left:0.35rem"
        data-confirm-submit="İtiraz kabul edilsin ve bu IP’nin yasağı kaldırılsın mı?">
    <input type="hidden" name="_csrf"      value="{csrf}">
    <input type="hidden" name="appeal_id"  value="{aid}">
    <input type="hidden" name="ip_hash"    value="{ip_hash}">
    <button type="submit" class="btn-success">✓ kabul et + yasağı kaldır</button>
  </form>
</td>
</tr>"#,
            ip_short = ip_short,
            reason = reason,
            age = escape_html(&age),
            csrf = escape_html(csrf_token),
            aid = a.id,
            ip_hash = escape_html(&a.ip_hash)
        );
    }
    appeal_rows
}

#[expect(
    clippy::too_many_lines,
    reason = "the moderation controls form one stable server-rendered HTML fragment"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the section interpolates independent pre-rendered moderation tables"
)]
/// Renders all moderation subsections and their counters.
fn render_admin_moderation_section(
    csrf_token: &str,
    report_rows: &str,
    appeal_rows: &str,
    ban_rows: &str,
    filter_rows: &str,
    report_badge: &str,
    appeal_badge: &str,
    ban_badge: &str,
    filter_badge: &str,
    moderation_summary_counter: &str,
    open_section: Option<&str>,
) -> String {
    let reports_open_attr = if open_section == Some("reports") {
        " open"
    } else {
        ""
    };
    format!(
        r#"<div class="admin-panel-moderation" id="moderation">
<section class="admin-section admin-section-collapsible" id="reports">
<details class="admin-dropdown" data-admin-dropdown-key="reports"{reports_open_attr}>
<summary><span>// moderasyon</span><span class="admin-dropdown-badges admin-dropdown-counter-label">{moderation_summary_counter}</span></summary>
<div class="admin-dropdown-content">
<p class="admin-moderation-intro">
  Önce inceleme kuyruklarına bak. Politika araçları ve log aşağıda.
</p>
<div class="admin-moderation-grid">
  <section class="admin-moderation-card admin-moderation-card-review">
    <div class="admin-card-header">
      <h3>// inceleme kuyruğu</h3>
      <p>Önce açık şikayetleri ve yasak itirazlarını ele al.</p>
    </div>
    <div class="admin-subsection admin-subsection-tight">
      <h4>// şikayet kutusu{report_badge}</h4>
      <div class="admin-table-wrap">
      <table class="admin-table">
        <thead><tr><th>gönderi</th><th>kullanıcı</th><th>içerik önizlemesi</th><th>sebep</th><th>tarih</th><th>işlem</th></tr></thead>
        <tbody>{report_rows}</tbody>
      </table>
      </div>
    </div>

    <div class="admin-subsection admin-subsection-tight">
      <h4 id="appeals">// yasak itirazları{appeal_badge}</h4>
      <div class="admin-table-wrap">
      <table class="admin-table">
        <thead><tr><th>ip (kısmi)</th><th>itiraz mesajı</th><th>tarih</th><th>işlem</th></tr></thead>
        <tbody>{appeal_rows}</tbody>
      </table>
      </div>
    </div>
  </section>

  <section class="admin-moderation-card admin-moderation-card-controls">
    <div class="admin-card-header">
      <h3>// politika kontrolleri</h3>
      <p>Yasakları ve otomatik kelime değiştirmeleri yönet.</p>
    </div>

    <div class="admin-subsection admin-subsection-tight" id="active-bans">
      <h4>// etkin yasaklar{ban_badge}</h4>
      <div class="admin-table-wrap">
      <table class="admin-table">
        <thead><tr><th>ip hash (kısmi)</th><th>sebep</th><th>bitiş</th><th>işlem</th></tr></thead>
        <tbody>{ban_rows}</tbody>
      </table>
      </div>
      <h4>yasak ekle</h4>
      <form method="POST" action="/admin/ban/add" class="admin-moderation-form admin-quick-form admin-moderation-compact-form">
        <input type="hidden" name="_csrf" value="{csrf}">
        <label class="admin-quick-field admin-moderation-field">IP hash
          <input class="admin-moderation-input" type="text" name="ip_hash" required placeholder="ab12cd34ef56...">
        </label>
        <label class="admin-quick-field admin-moderation-field">Sebep
          <input class="admin-moderation-input" type="text" name="reason" placeholder="Kural ihlali">
        </label>
        <label class="admin-quick-field admin-quick-field-compact admin-moderation-field">Süre (saat)
          <input class="admin-moderation-input" type="text" name="duration_hours" placeholder="boş = kalıcı" inputmode="numeric">
        </label>
        <button type="submit">yasakla</button>
      </form>
    </div>

    <div class="admin-subsection admin-subsection-tight" id="word-filters">
      <h4>// kelime filtreleri{filter_badge}</h4>
      <div class="admin-table-wrap">
      <table class="admin-table">
        <thead><tr><th>desen</th><th>değiştirme</th><th>işlem</th></tr></thead>
        <tbody>{filter_rows}</tbody>
      </table>
      </div>
      <h4>filtre ekle</h4>
      <form method="POST" action="/admin/filter/add" class="admin-moderation-form admin-quick-form admin-moderation-compact-form">
        <input type="hidden" name="_csrf" value="{csrf}">
        <label class="admin-quick-field admin-moderation-field">Desen
          <input class="admin-moderation-input" type="text" name="pattern" required placeholder="eski ifade">
        </label>
        <label class="admin-quick-field admin-moderation-field">Değiştirme
          <input class="admin-moderation-input" type="text" name="replacement" placeholder="yeni ifade">
        </label>
        <button type="submit">ekle</button>
      </form>
    </div>
  </section>

  <section class="admin-moderation-card admin-moderation-card-log">
    <div class="admin-card-header">
      <h3>// denetim kaydı</h3>
      <p>Her moderasyon işlemi burada kaydedilir.</p>
    </div>
    <div class="admin-card-actions">
      <a href="/admin/mod-log" class="admin-link-button">tam logu gör</a>
    </div>
    <p class="admin-card-note">Geçmiş ve takip için tam logu kullan. Canlı kuyruklar bu panelde görünmeye devam eder.</p>
  </section>
</div>
</div>
</details>
</section>
</div>"#,
        csrf = escape_html(csrf_token),
        report_rows = report_rows,
        appeal_rows = appeal_rows,
        ban_rows = ban_rows,
        filter_rows = filter_rows,
        report_badge = report_badge,
        appeal_badge = appeal_badge,
        ban_badge = ban_badge,
        filter_badge = filter_badge,
        moderation_summary_counter = escape_html(moderation_summary_counter),
    )
}

#[cfg(test)]
mod tests {
    use super::render_appeal_rows;
    use crate::models::BanAppeal;

    #[test]
    fn appeal_ip_prefix_is_escaped_for_html_like_and_multibyte_input() {
        let script_tag = ["<", "script", ">"].concat();
        let script_close = ["</", "script", ">"].concat();
        let multibyte_attack = format!("éééé{script_tag}alert(1){script_close}");
        let appeals = [
            BanAppeal {
                id: 1,
                ip_hash: "<img src=x onerror=alert(1)>".to_owned(),
                reason: "html-like".to_owned(),
                status: "open".to_owned(),
                created_at: 1,
            },
            BanAppeal {
                id: 2,
                ip_hash: multibyte_attack,
                reason: "multibyte".to_owned(),
                status: "open".to_owned(),
                created_at: 2,
            },
        ];

        let rows = render_appeal_rows("csrf", &appeals);

        assert!(rows.contains("&lt;img src=x oner"));
        assert!(!rows.contains("<img"));
        assert!(!rows.contains(&script_tag));
        assert!(rows.contains("éééé&lt;script&gt;"));
    }
}
