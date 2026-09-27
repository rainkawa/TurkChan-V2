//! Appearance, theme, favicon, and banner sections of the admin panel.

use super::{
    escape_html, render_banner_asset_list, render_banner_upload_form, render_board_appearance_card,
    AdminPanelViewModel,
};
use crate::theme_builder::{
    builder_defaults_for_preset, parse_builder_config, ThemeBuilderConfig, ThemeDensity,
    ThemeFontFamily, BUILDER_PRESETS,
};
use std::fmt::Write as _;

/// Renders the general site-identity settings section.
pub(super) fn render_site_settings(view: &AdminPanelViewModel<'_>) -> String {
    let global_favicon_exists = crate::favicon::global_has_custom_favicon();
    let global_favicon_version =
        crate::favicon::favicon_version_for_board(None).unwrap_or_default();
    let global_favicon_preview = if global_favicon_exists {
        format!(
            r#"<img class="favicon-inline-preview" src="/favicon-32x32.png?v={version}" alt="global favicon">"#,
            version = escape_html(&global_favicon_version)
        )
    } else {
        String::new()
    };
    let global_favicon_label = if global_favicon_exists {
        "favicon değiştir"
    } else {
        "genel favicon"
    };
    let global_favicon_button = if global_favicon_exists {
        "değiştir"
    } else {
        "yükle"
    };
    let global_favicon_status = if global_favicon_exists {
        "Özel genel favicon etkin ve rustchan-data/runtime/favicon/ altında saklanıyor."
    } else {
        "Henüz özel genel favicon yüklenmedi."
    };
    let public_url_help = if view.dashboard.public_url == "not configured" {
        "Genel URL yapılandırılmadı. settings.toml içindeki public_hosts listesine en az bir ana makine adı ekle, ardından TurkChan’ı yeniden başlat."
    } else {
        "Çalışma zamanı ana makine güveni settings.toml içindeki public_hosts değerini kullanır. Bu URL’yi değiştirmek için public_hosts değerini düzenle ve TurkChan’ı yeniden başlat."
    };

    render_admin_site_settings_section(
        view.csrf_token,
        view.appearance.site_name,
        view.appearance.site_subtitle,
        view.appearance.homepage_new_thread_badges_enabled,
        view.appearance.homepage_new_reply_badges_enabled,
        view.appearance.thread_new_reply_badges_enabled,
        &render_enabled_theme_options(view),
        view.dashboard.public_url,
        public_url_help,
        &global_favicon_preview,
        global_favicon_label,
        global_favicon_button,
        global_favicon_status,
    )
}

/// Renders the complete appearance tab of the admin panel.
pub(super) fn render(view: &AdminPanelViewModel<'_>) -> String {
    let theme_catalog_open_attr = if view.open_section == Some("theme-catalog") {
        " open"
    } else {
        ""
    };
    let banner_settings_open_attr = if matches!(
        view.open_section,
        Some("board-banners" | "global-banners" | "home-banners")
    ) || view
        .open_section
        .is_some_and(|section| section.starts_with("board-appearance-"))
    {
        " open"
    } else {
        ""
    };
    let banner_external_links_enabled_checked = if view.appearance.banner_external_links_enabled {
        " checked"
    } else {
        ""
    };
    let global_banner_upload_form = render_banner_upload_form(
        "/admin/site/banner",
        view.csrf_token,
        None,
        view.boards,
        true,
        "genel banner yükle",
    );
    let home_banner_upload_form = render_banner_upload_form(
        "/admin/home/banner",
        view.csrf_token,
        None,
        view.boards,
        false,
        "ana sayfa bannerı yükle",
    );
    let global_banner_rows = render_banner_asset_list(
        view.appearance.global_banners,
        view.csrf_token,
        view.boards,
        true,
        "Henüz genel board bannerı yüklenmedi.",
    );
    let home_banner_rows = render_banner_asset_list(
        view.appearance.home_banners,
        view.csrf_token,
        view.boards,
        false,
        "Henüz ana sayfa bannerı yüklenmedi.",
    );
    let (builtin_theme_cards, custom_theme_cards) = render_theme_cards(view);
    let custom_theme_cards_or_empty = if custom_theme_cards.is_empty() {
        r#"<div class="theme-empty-state">Henüz özel tema yok. Yukarıdan bir tane oluştur, burada görünsün.</div>"#.to_owned()
    } else {
        custom_theme_cards
    };

    render_admin_appearance_section(
        view.csrf_token,
        view.appearance.banner_rotation_interval_minutes,
        banner_external_links_enabled_checked,
        banner_settings_open_attr,
        &global_banner_upload_form,
        &global_banner_rows,
        &home_banner_upload_form,
        &home_banner_rows,
        &render_board_appearance_cards(view),
        theme_catalog_open_attr,
        &builtin_theme_cards,
        &custom_theme_cards_or_empty,
    )
}

/// Renders selectable options for every enabled theme.
fn render_enabled_theme_options(view: &AdminPanelViewModel<'_>) -> String {
    let mut enabled_theme_options = String::new();
    for theme in view.appearance.themes.iter().filter(|theme| theme.enabled) {
        let _ = write!(
            enabled_theme_options,
            r#"<option value="{slug}"{selected}>{label}</option>"#,
            slug = escape_html(&theme.slug),
            selected = if theme.slug == view.appearance.default_theme {
                " selected"
            } else {
                ""
            },
            label = escape_html(&theme.display_name)
        );
    }
    enabled_theme_options
}

/// Renders per-board appearance and banner settings cards.
fn render_board_appearance_cards(view: &AdminPanelViewModel<'_>) -> String {
    let mut board_appearance_cards = String::new();
    for board in view.boards {
        let board_assets = view
            .appearance
            .board_banners
            .iter()
            .filter(|asset| {
                asset.scope == crate::models::BannerScope::Board && asset.board_id == Some(board.id)
            })
            .cloned()
            .collect::<Vec<_>>();
        board_appearance_cards.push_str(&render_board_appearance_card(
            board,
            view.boards,
            view.csrf_token,
            view.appearance.themes,
            &board_assets,
            view.open_section,
        ));
    }
    board_appearance_cards
}

/// Renders theme-builder preset options and marks the selected preset.
fn render_preset_options(selected_slug: &str) -> String {
    let mut out = String::new();
    for preset in BUILDER_PRESETS {
        let _ = write!(
            out,
            r#"<option value="{slug}"{selected}>{label}</option>"#,
            slug = escape_html(preset.slug),
            selected = if preset.slug == selected_slug {
                " selected"
            } else {
                ""
            },
            label = escape_html(preset.label),
        );
    }
    out
}

/// Renders a paired color picker and hexadecimal input.
fn render_color_control(label: &str, name: &str, value: &str, help: &str) -> String {
    format!(
        r##"<div class="theme-builder-color-field">
  <span class="theme-builder-field-label">{label}</span>
  <span class="theme-builder-color-row">
    <input type="color" value="{value}" data-theme-builder-color-for="{name}" aria-label="{label} renk seçici">
    <label class="theme-builder-hex-field"><span>Hex</span><input type="text" name="{name}" value="{value}" maxlength="7" pattern="#[0-9A-Fa-f]{{6}}" spellcheck="false" data-theme-builder-field="{name}"></label>
  </span>
  <small>{help}</small>
</div>"##,
        label = escape_html(label),
        name = escape_html(name),
        value = escape_html(value),
        help = escape_html(help),
    )
}

/// Renders a labeled group of related theme color controls.
fn render_color_group(title: &str, description: &str, controls: &str) -> String {
    format!(
        r#"<div class="theme-builder-color-group">
  <div class="theme-builder-group-header">
    <h4>{title}</h4>
    <p>{description}</p>
  </div>
  <div class="theme-builder-colors-grid">{controls}</div>
</div>"#,
        title = escape_html(title),
        description = escape_html(description),
        controls = controls,
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "the builder controls mirror one cohesive theme-editing form"
)]
/// Renders all guided theme-builder control sections.
fn render_builder_sections(config: &ThemeBuilderConfig) -> String {
    let basics = format!(
        r#"<details class="theme-builder-section" open>
  <summary><span>Temel ayarlar</span><small>Hazır ayar, sıkılık, yazı tipi ve köşe biçimi.</small></summary>
  <div class="theme-builder-section-body board-settings-grid">
    <label>Başlangıç hazır ayarı
      <select name="base_preset" data-theme-builder-field="base_preset">{preset_options}</select>
      <small>İstediğine en yakın yerleşik temayı seç, sonra buradan ayarla.</small>
      <noscript><small>Seçili hazır ayardan başlamak için tema adını ve kısa adını doldur, sonra varsayılanlarını kaydet. Elle yaptığın renk değişikliklerini korumak için normal kaydet butonunu kullan.</small>
      <button type="submit" name="apply_preset" value="1">Hazır ayar varsayılanlarını kaydet</button></noscript>
    </label>
    <label>Sıkılık
      <select name="density" data-theme-builder-field="density">
        <option value="cozy"{cozy_selected}>Ferah</option>
        <option value="compact"{compact_selected}>Sık</option>
      </select>
      <small>Sık seçenek, gönderilerin ve kartların çevresindeki boşluğu azaltır.</small>
    </label>
    <label>Yazı tipi ailesi
      <select name="font_family" data-theme-builder-field="font_family">
        <option value="system_sans"{sans_selected}>Sistem Sans</option>
        <option value="system_serif"{serif_selected}>Sistem Serif</option>
        <option value="system_mono"{mono_selected}>Sistem Mono</option>
      </select>
      <small>Yalnızca sistem yazı tipleri, böylece kayıtlı temalar hafif ve güvenli kalır.</small>
    </label>
    <label>Kenarlık yarıçapı
      <input type="range" name="border_radius_px" min="0" max="24" step="1" value="{radius}" data-theme-builder-field="border_radius_px">
      <span class="theme-builder-range-value" data-theme-builder-range-value="border_radius_px">{radius}px</span>
      <small>Düşük değerler daha keskin, yüksek değerler daha yumuşak görünür.</small>
    </label>
  </div>
</details>"#,
        preset_options = render_preset_options(&config.base_preset),
        cozy_selected = if config.density == ThemeDensity::Cozy {
            " selected"
        } else {
            ""
        },
        compact_selected = if config.density == ThemeDensity::Compact {
            " selected"
        } else {
            ""
        },
        sans_selected = if config.font_family == ThemeFontFamily::Sans {
            " selected"
        } else {
            ""
        },
        serif_selected = if config.font_family == ThemeFontFamily::Serif {
            " selected"
        } else {
            ""
        },
        mono_selected = if config.font_family == ThemeFontFamily::Mono {
            " selected"
        } else {
            ""
        },
        radius = config.border_radius_px,
    );
    let page_colors = format!(
        "{background}{panel}{border}",
        background = render_color_control(
            "Sayfa arka planı",
            "background_color",
            &config.background_color,
            "Boardların, konuların ve admin yüzeylerinin arkasındaki ana sayfa arka planı.",
        ),
        panel = render_color_control(
            "Panel arka planı",
            "panel_color",
            &config.panel_color,
            "Board kartları, admin bölümleri ve büyük içerik kutuları.",
        ),
        border = render_color_control(
            "Kenarlıklar ve ayırıcılar",
            "border_color",
            &config.border_color,
            "Genel çerçeveler, ayırıcılar ve ince ayrım çizgileri.",
        ),
    );
    let text_colors = format!(
        "{text}{muted}{link}{link_hover}{quote}{meta}",
        text = render_color_control(
            "Ana metin",
            "text_color",
            &config.text_color,
            "Okunabilir birincil metin.",
        ),
        muted = render_color_control(
            "İkincil metin",
            "muted_text_color",
            &config.muted_text_color,
            "Yardımcı metinler, daha soluk etiketler ve sakin ayrıntılar.",
        ),
        link = render_color_control(
            "Bağlantılar",
            "link_color",
            &config.link_color,
            "Normal bağlantı rengi.",
        ),
        link_hover = render_color_control(
            "Üzerine gelindiğinde bağlantılar",
            "link_hover_color",
            &config.link_hover_color,
            "İmleç bağlantının üzerindeyken aldığı renk.",
        ),
        quote = render_color_control(
            "Alıntılanan metin",
            "quote_color",
            &config.quote_color,
            "Greentext ve alıntı satırları.",
        ),
        meta = render_color_control(
            "Gönderi ayrıntıları",
            "meta_text_color",
            &config.meta_text_color,
            "Zaman damgaları, gönderi numaraları ve ikincil gönderi bilgileri.",
        ),
    );
    let status_colors = format!(
        "{success}{danger}",
        success = render_color_control(
            "Başarı durumu",
            "success_color",
            &config.success_color,
            "Olumlu bildirimler ve başarı vurguları.",
        ),
        danger = render_color_control(
            "Uyarı durumu",
            "danger_color",
            &config.danger_color,
            "Uyarılar, doğrulama mesajları ve hata vurguları.",
        ),
    );
    let colors = format!(
        r#"<details class="theme-builder-section" open>
  <summary><span>Renkler</span><small>Temel sayfa, metin, bağlantı ve durum renkleri.</small></summary>
  <div class="theme-builder-section-body theme-builder-group-stack">
    {page_group}{text_group}{status_group}
  </div>
</details>"#,
        page_group = render_color_group(
            "Sayfa ve arka plan",
            "Siteyi çerçeveleyen geniş yüzeyler.",
            &page_colors,
        ),
        text_group = render_color_group(
            "Metin ve bağlantılar",
            "Okunabilir metin, bağlantı, alıntı ve gönderi üstverisi.",
            &text_colors,
        ),
        status_group = render_color_group(
            "Bildirimler ve durumlar",
            "Başarı ve doğrulama mesajlarında kullanılan geri bildirim renkleri.",
            &status_colors,
        ),
    );
    let post_colors = format!(
        "{card}{op_card}{header_bg}{header_text}{header_border}",
        card = render_color_control(
            "Yanıt kartı arka planı",
            "card_color",
            &config.card_color,
            "Normal yanıt kartları ve gönderi kutuları.",
        ),
        op_card = render_color_control(
            "Konu açıcı gönderi arka planı",
            "op_card_color",
            &config.op_card_color,
            "İlk gönderi kartının arka planı.",
        ),
        header_bg = render_color_control(
            "Site başlığı arka planı",
            "header_background_color",
            &config.header_background_color,
            "Üst site çubuğunun arka planı.",
        ),
        header_text = render_color_control(
            "Site başlığı metni",
            "header_text_color",
            &config.header_text_color,
            "Üst site çubuğundaki bağlantılar ve etiketler.",
        ),
        header_border = render_color_control(
            "Site başlığı kenarlığı",
            "header_border_color",
            &config.header_border_color,
            "Üst site çubuğunun alt kenarlığı.",
        ),
    );
    let posts = format!(
        r#"<details class="theme-builder-section">
  <summary><span>Gönderiler/kartlar</span><small>Kartlar, yanıtlar, konu açıcı gönderiler ve site başlığı.</small></summary>
  <div class="theme-builder-section-body theme-builder-group-stack">
    {post_group}
  </div>
</details>"#,
        post_group = render_color_group(
            "Kartlar ve gezinme",
            "Gönderi yüzeyleri ve onları çerçeveleyen başlık.",
            &post_colors,
        ),
    );
    let input_colors = format!(
        "{input_bg}{input_text}{input_border}",
        input_bg = render_color_control(
            "Alan arka planı",
            "input_background_color",
            &config.input_background_color,
            "Metin alanlarının ve çok satırlı alanın arka planı.",
        ),
        input_text = render_color_control(
            "Alan metni",
            "input_text_color",
            &config.input_text_color,
            "Alanların içindeki metin.",
        ),
        input_border = render_color_control(
            "Alan kenarlığı",
            "input_border_color",
            &config.input_border_color,
            "Form alanlarının çerçevesi.",
        ),
    );
    let button_colors = format!(
        "{button_bg}{button_text}{button_border}{button_hover}",
        button_bg = render_color_control(
            "Buton arka planı",
            "button_background_color",
            &config.button_background_color,
            "Varsayılan buton arka planı.",
        ),
        button_text = render_color_control(
            "Buton metni",
            "button_text_color",
            &config.button_text_color,
            "Buton etiketinin rengi.",
        ),
        button_border = render_color_control(
            "Buton kenarlığı",
            "button_border_color",
            &config.button_border_color,
            "Buton çerçevesinin rengi.",
        ),
        button_hover = render_color_control(
            "Buton üzerine gelme arka planı",
            "button_hover_color",
            &config.button_hover_color,
            "Üzerine gelindiğinde buton arka planı.",
        ),
    );
    let forms = format!(
        r#"<details class="theme-builder-section">
  <summary><span>Formlar/butonlar</span><small>Alanlar, çok satırlı alanlar ve eylem butonları.</small></summary>
  <div class="theme-builder-section-body theme-builder-group-stack">
    {input_group}{button_group}
  </div>
</details>"#,
        input_group = render_color_group(
            "Form alanları",
            "Gönderi ve admin formlarında kullanılan alanlar.",
            &input_colors,
        ),
        button_group = render_color_group(
            "Butonlar",
            "Birincil eylem butonları ve üzerine gelme hâlleri.",
            &button_colors,
        ),
    );
    let advanced = format!(
        r#"<details class="theme-builder-section">
  <summary><span>Gelişmiş/eski CSS</span><small>Eski temalar ya da küçük rötuşlar için elle CSS.</small></summary>
  <div class="theme-builder-section-body">
    <div class="theme-builder-warning">Rehberli oluşturucu alanları daha güvenli ve bakımı kolaydır. Elle CSS’yi yalnızca eski/elle temalar ya da küçük kapsamlı geçersiz kılmalar için kullan; içe aktarma ve betiğe benzeyen adresler reddedilir.</div>
    <label>Elle CSS geçersiz kılmaları
      <textarea name="advanced_css" rows="8" spellcheck="false" data-theme-builder-field="advanced_css">{advanced_css}</textarea>
      <small>İsteğe bağlı. Geçersiz kılmaları bu temayla sınırlı tut ki yerleşik temalara sızmasın.</small>
    </label>
  </div>
</details>"#,
        advanced_css = escape_html(&config.advanced_css),
    );

    format!("{basics}{colors}{posts}{forms}{advanced}")
}

/// Renders a representative live preview for a guided theme.
fn render_builder_preview(config: &ThemeBuilderConfig, slug: &str) -> String {
    let mut preview_style = format!(
        "color-scheme:{};",
        crate::theme_builder::input_color_scheme(&config.input_background_color)
    );
    for (property, value) in [
        ("bg", &config.background_color),
        ("panel", &config.panel_color),
        ("card", &config.card_color),
        ("op", &config.op_card_color),
        ("text", &config.text_color),
        ("muted", &config.muted_text_color),
        ("link", &config.link_color),
        ("link-hover", &config.link_hover_color),
        ("border", &config.border_color),
        ("input-bg", &config.input_background_color),
        ("input-text", &config.input_text_color),
        ("input-border", &config.input_border_color),
        ("button-bg", &config.button_background_color),
        ("button-text", &config.button_text_color),
        ("button-border", &config.button_border_color),
        ("button-hover", &config.button_hover_color),
        ("header-bg", &config.header_background_color),
        ("header-text", &config.header_text_color),
        ("header-border", &config.header_border_color),
        ("quote", &config.quote_color),
        ("meta", &config.meta_text_color),
        ("success", &config.success_color),
        ("danger", &config.danger_color),
    ] {
        let _ = write!(preview_style, "--theme-preview-{property}:{value};");
    }
    let (gap, padding) = match config.density {
        ThemeDensity::Compact => ("0.35rem", "0.45rem"),
        ThemeDensity::Cozy => ("0.55rem", "0.75rem"),
    };
    let _ = write!(
        preview_style,
        "--theme-preview-radius:{}px;--theme-preview-font:{};--theme-preview-gap:{gap};--theme-preview-pad:{padding};",
        config.border_radius_px,
        config.font_family.css_stack(),
    );
    format!(
        r##"<section class="theme-builder-preview-card">
  <div class="admin-card-header">
    <h4>Tema önizleme</h4>
    <p>JavaScript kullanılabilir olduğunda temsilî TurkChan yüzeyleri güncellenir. Kaydetme yine formu normal şekilde gönderir.</p>
  </div>
  <style data-theme-preview-style></style>
  <div class="theme-preview-shell" style="{preview_style}" data-theme-preview data-theme-preview-slug="{slug}" data-theme-preview-preset="{preset}">
    <div class="theme-preview-header">
      <span class="theme-preview-title">TurkChan</span>
      <nav class="theme-preview-nav"><a href="#">/tech/</a> <a href="#">/art/</a> <a href="#">/mu/</a></nav>
    </div>
    <div class="theme-preview-panels">
      <article class="theme-preview-panel">
        <div class="theme-preview-card-title">/tech/</div>
        <p class="theme-preview-muted">Board alt başlığı ve ana sayfa kartı özeti.</p>
        <a href="#">board’u aç</a>
      </article>
      <article class="theme-preview-post theme-preview-op">
        <div class="theme-preview-meta">OP 04/29/2026 No.101 <a href="#">>>102</a></div>
        <p><span class="theme-preview-quote">&gt; alıntılanan satır</span><br>Bir <a href="#">bağlantı</a> içeren konu açıcı içerik.</p>
      </article>
      <article class="theme-preview-post">
        <div class="theme-preview-meta">Yanıt No.102 <a href="#">>>101</a></div>
        <p>Üstveri, alıntı bağlantıları ve normal gövde metni içeren yanıt kartı.</p>
      </article>
      <div class="theme-preview-form">
        <input type="text" value="Ad" aria-label="Önizleme adı">
        <textarea rows="3" aria-label="Önizleme gövdesi">Gövde metni</textarea>
        <div class="theme-preview-actions">
          <button type="button">Gönder</button>
          <button type="button" class="theme-preview-secondary">Önizle</button>
        </div>
      </div>
      <div class="theme-preview-flashes">
        <div class="admin-flash flash-ok">Kaydedilen tema önizlemesi</div>
        <div class="admin-flash flash-error">Doğrulama mesajı önizlemesi</div>
      </div>
    </div>
  </div>
</section>"##,
        slug = escape_html(slug),
        preset = escape_html(&config.base_preset),
        preview_style = escape_html(&preview_style),
    )
}

/// Renders the guided editor for a theme-builder configuration.
fn render_builder_editor(theme_slug: &str, config: &ThemeBuilderConfig) -> String {
    format!(
        r#"<input type="hidden" name="theme_mode" value="builder">
<div class="theme-builder-shell" data-theme-builder>
  <div class="theme-builder-controls">
    {sections}
  </div>
  {preview}
</div>"#,
        sections = render_builder_sections(config),
        preview = render_builder_preview(config, theme_slug),
    )
}

/// Renders the raw CSS editor retained for legacy themes.
fn render_legacy_editor(theme_slug: &str, custom_css: &str) -> String {
    format!(
        r#"<input type="hidden" name="theme_mode" value="legacy">
<div class="theme-editor-built-in-note">
  <p>Bu, eski tip bir özel CSS teması. Uyumluluk için TurkChan onu olduğu gibi yüklemeye devam eder. Rehberli oluşturucu temaları daha güvenli ve bakımı kolaydır; bu düzenleyici yalnızca eski/elle CSS içindir.</p>
</div>
<div class="theme-editor-css-panel">
  <div class="theme-editor-panel-header">
    <h4>Gelişmiş/eski CSS</h4>
    <p>Her şeyi <code>html[data-theme="{slug}"]</code> ile kapsamlandır. Bu, gelişmiş çıkış yoludur.</p>
  </div>
  <textarea name="custom_css" rows="18" spellcheck="false">{custom_css}</textarea>
  <p class="theme-editor-code-note">Eski temalar geçiş yapmaya gerek kalmadan çalışmaya devam eder. Yeni rehberli temalar ham CSS yerine yukarıdaki oluşturucuyu kullanır.</p>
</div>"#,
        slug = escape_html(theme_slug),
        custom_css = escape_html(custom_css),
    )
}

/// Renders editable or read-only metadata fields for a theme.
fn render_theme_metadata_fields(theme: &crate::models::Theme) -> String {
    if theme.is_builtin {
        format!(
            r#"<div class="board-settings-grid">
        <label>Görünen ad<input type="text" value="{name}" maxlength="64" readonly aria-readonly="true"></label>
        <label>Kısa ad<input type="text" value="{slug}" maxlength="32" readonly aria-readonly="true"></label>
        <label>Renk örneği<input type="color" value="{swatch}" disabled></label>
      </div>
      <div class="board-settings-grid" style="margin-top:0.65rem">
        <label>Açıklama<input type="text" value="{description}" maxlength="256" readonly aria-readonly="true"></label>
      </div>
      <p class="admin-meta-note">Yerleşik tema üstverisi TurkChan tarafından yönetilir ve buradan düzenlenemez. Yalnızca seçicideki görünürlük değiştirilebilir.</p>"#,
            name = escape_html(&theme.display_name),
            slug = escape_html(&theme.slug),
            swatch = escape_html(&theme.swatch_hex),
            description = escape_html(&theme.description),
        )
    } else {
        format!(
            r#"<div class="board-settings-grid">
        <label>Görünen ad<input type="text" name="display_name" value="{name}" maxlength="64" required></label>
        <label>Kısa ad<input type="text" name="slug" value="{slug}" maxlength="32"></label>
        <label>Tema seçici renk örneği<input type="color" name="swatch_hex" value="{swatch}"></label>
      </div>
      <div class="board-settings-grid" style="margin-top:0.65rem">
        <label>Açıklama<input type="text" name="description" value="{description}" maxlength="256"></label>
      </div>"#,
            name = escape_html(&theme.display_name),
            slug = escape_html(&theme.slug),
            swatch = escape_html(&theme.swatch_hex),
            description = escape_html(&theme.description),
        )
    }
}

/// Renders built-in and custom theme cards as separate HTML groups.
fn render_theme_cards(view: &AdminPanelViewModel<'_>) -> (String, String) {
    let mut builtin_theme_cards = String::new();
    let mut custom_theme_cards = String::new();
    for theme in view.appearance.themes {
        let theme_editor = if theme.is_builtin {
            r#"<div class="theme-editor-built-in-note">
<p>Yerleşik temalar <code>static/style.css</code> içinde tutulur. Buradan seçicide görünüp görünmeyeceğini değiştirebilirsin, ancak rehberli düzenleme özel temalara ayrılmıştır; böylece gelen hazır ayarlar kararlı kalır.</p>
</div>"#.to_owned()
        } else if let Some(builder_config) = parse_builder_config(&theme.custom_css) {
            render_builder_editor(&theme.slug, &builder_config)
        } else {
            render_legacy_editor(&theme.slug, &theme.custom_css)
        };
        let card_markup = format!(
            r#"<details class="board-settings-card theme-editor-card" id="theme-{slug}">
<summary class="theme-card-summary">
  <span class="theme-card-swatch" style="--theme-swatch:{swatch}"></span>
  <span class="theme-card-heading">
    <strong>{name}</strong>
    <span class="theme-card-meta"><code>{slug}</code>{builtin_tag}{disabled_tag}</span>
  </span>
  <span class="theme-card-description">{description}</span>
</summary>
<form method="POST" action="/admin/theme/update" class="board-settings-form theme-editor-form">
  <input type="hidden" name="_csrf" value="{csrf}">
  <input type="hidden" name="existing_slug" value="{slug}">
  <div class="theme-editor-layout">
    <div class="theme-editor-basics">
      {metadata_fields}
      <div class="board-settings-checks">
        <label><input type="checkbox" name="enabled" value="1"{enabled_ck}> Tema seçicide etkin</label>
      </div>
      {theme_editor}
    </div>
  </div>
  <div class="board-settings-actions">
    <button type="submit">tema ayarlarını kaydet</button>
  </div>
</form>
{delete_form}
</details>"#,
            csrf = escape_html(view.csrf_token),
            name = escape_html(&theme.display_name),
            slug = escape_html(&theme.slug),
            swatch = escape_html(&theme.swatch_hex),
            builtin_tag = if theme.is_builtin {
                r#" <span class="tag">yerleşik</span>"#
            } else {
                r#" <span class="tag">özel</span>"#
            },
            disabled_tag = if theme.enabled {
                ""
            } else {
                r#" <span class="tag locked">devre dışı</span>"#
            },
            description = if theme.description.trim().is_empty() {
                "Henüz açıklama yok.".to_owned()
            } else {
                escape_html(&theme.description)
            },
            enabled_ck = if theme.enabled { " checked" } else { "" },
            metadata_fields = render_theme_metadata_fields(theme),
            theme_editor = theme_editor,
            delete_form = if theme.is_builtin {
                String::new()
            } else {
                format!(
                    r#"<form method="POST" action="/admin/theme/delete" class="theme-editor-delete">
  <input type="hidden" name="_csrf" value="{csrf}">
  <input type="hidden" name="slug" value="{slug}">
  <button type="submit" class="btn-danger" data-confirm="{slug} özel teması silinsin mi?">temayı sil</button>
</form>"#,
                    csrf = escape_html(view.csrf_token),
                    slug = escape_html(&theme.slug)
                )
            }
        );
        if theme.is_builtin {
            builtin_theme_cards.push_str(&card_markup);
        } else {
            custom_theme_cards.push_str(&card_markup);
        }
    }
    (builtin_theme_cards, custom_theme_cards)
}

/// Renders a button for copying the configured public URL.
fn render_public_url_copy_button(public_url: &str) -> String {
    if public_url == "not configured" {
        String::new()
    } else {
        format!(
            r#"<button type="button" class="admin-copy-button" data-admin-copy-text="{public_url}" hidden>Kopyala</button>"#,
            public_url = escape_html(public_url),
        )
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the section interpolates independent pre-rendered controls into fixed HTML"
)]
/// Renders the site identity and favicon settings section.
fn render_admin_site_settings_section(
    csrf_token: &str,
    site_name_val: &str,
    site_subtitle_val: &str,
    homepage_new_thread_badges_enabled: bool,
    homepage_new_reply_badges_enabled: bool,
    thread_new_reply_badges_enabled: bool,
    enabled_theme_options: &str,
    public_url: &str,
    public_url_help: &str,
    global_favicon_preview: &str,
    global_favicon_label: &str,
    global_favicon_button: &str,
    global_favicon_status: &str,
) -> String {
    let public_url_copy_button = render_public_url_copy_button(public_url);
    format!(
        r#"<div class="admin-panel-site-settings" id="site-settings-panel">
<section class="admin-section" id="site-settings">
<h2>// site ayarları</h2>
<form method="POST" action="/admin/site/settings" class="admin-site-settings-form">
<input type="hidden" name="_csrf" value="{csrf}">
<div class="board-settings-grid admin-settings-grid">
  <label>Site adı
    <input type="text" name="site_name" value="{site_name_val}" maxlength="64" placeholder="TurkChan"
           style="font-family:inherit">
  </label>
  <label>Ana sayfa alt başlığı
    <input type="text" name="site_subtitle" value="{site_subtitle_val}" maxlength="128" placeholder="devam etmek için bir board seç"
           style="font-family:inherit">
  </label>
  <label>Varsayılan tema
    <select name="default_theme" style="font-family:inherit;padding:0.25rem 0.4rem;background:var(--bg-input);color:var(--text)">
      {enabled_theme_options}
    </select>
  </label>
</div>
<div class="board-settings-checks">
  <label class="admin-inline-checkbox">
    <input type="checkbox" name="homepage_new_thread_badges_enabled" value="1"{homepage_new_thread_badges_enabled_checked}>
    Ana sayfa board kartlarında yeni konu rozetleri
  </label>
  <label class="admin-inline-checkbox">
    <input type="checkbox" name="homepage_new_reply_badges_enabled" value="1"{homepage_new_reply_badges_enabled_checked}>
    Ana sayfada yeni yanıt rozetlerini göster
  </label>
  <label class="admin-inline-checkbox">
    <input type="checkbox" name="thread_new_reply_badges_enabled" value="1"{thread_new_reply_badges_enabled_checked}>
    Board/katalog konu kartlarında yeni yanıt rozetleri
  </label>
</div>
<p class="admin-meta-note admin-meta-note-spaced">
  Ana sayfadaki yeni konuları, ana sayfadaki yeni yanıtları ve board dizini/katalog kartlarındaki yeni yanıtları birbirinden bağımsız izle.
</p>
<div class="board-settings-actions">
  <button type="submit">ayarları kaydet</button>
</div>
</form>
<div class="admin-subsection admin-subsection-tight" id="public-url-settings">
  <div class="admin-card-header">
    <h3>// genel URL</h3>
    <p>Şu anda yapılandırılmış genel giriş noktası.</p>
  </div>
  <p class="admin-copy admin-copy-action-row"><strong>{public_url}</strong>{public_url_copy_button}</p>
  <p class="admin-meta-note">{public_url_help}</p>
</div>
<div class="favicon-inline-row favicon-inline-row-global">
{global_favicon_preview}
<form method="POST" action="/admin/site/favicon" enctype="multipart/form-data" class="favicon-inline-form">
<input type="hidden" name="_csrf" value="{csrf}">
<label class="favicon-inline-label">
  {global_favicon_label}
  <input type="file" name="favicon" accept="image/png,image/jpeg,image/webp" required class="favicon-inline-input">
</label>
<button type="submit">{global_favicon_button}</button>
</form>
</div>
<p class="admin-meta-note admin-meta-note-spaced">
  {global_favicon_status}
</p>
</section>
</div>"#,
        csrf = escape_html(csrf_token),
        site_name_val = escape_html(site_name_val),
        site_subtitle_val = escape_html(site_subtitle_val),
        homepage_new_thread_badges_enabled_checked = if homepage_new_thread_badges_enabled {
            " checked"
        } else {
            ""
        },
        homepage_new_reply_badges_enabled_checked = if homepage_new_reply_badges_enabled {
            " checked"
        } else {
            ""
        },
        thread_new_reply_badges_enabled_checked = if thread_new_reply_badges_enabled {
            " checked"
        } else {
            ""
        },
        enabled_theme_options = enabled_theme_options,
        public_url = escape_html(public_url),
        public_url_help = escape_html(public_url_help),
        public_url_copy_button = public_url_copy_button,
        global_favicon_preview = global_favicon_preview,
        global_favicon_label = global_favicon_label,
        global_favicon_button = global_favicon_button,
        global_favicon_status = global_favicon_status,
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "the appearance section is one stable server-rendered HTML fragment"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the section interpolates independent pre-rendered appearance controls"
)]
/// Renders the banner and theme-management sections.
fn render_admin_appearance_section(
    csrf_token: &str,
    banner_rotation_interval_minutes: i64,
    banner_external_links_enabled_checked: &str,
    banner_settings_open_attr: &str,
    global_banner_upload_form: &str,
    global_banner_rows: &str,
    home_banner_upload_form: &str,
    home_banner_rows: &str,
    board_appearance_cards: &str,
    theme_catalog_open_attr: &str,
    builtin_theme_cards: &str,
    custom_theme_cards_or_empty: &str,
) -> String {
    let starter_builder = builder_defaults_for_preset("forest");
    format!(
        r##"<div class="admin-panel-appearance" id="appearance">
<section class="admin-section admin-section-collapsible" id="board-banners">
<details class="admin-dropdown" data-admin-dropdown-key="board-banners"{banner_settings_open_attr}>
<summary>// board bannerları &amp; favicon’ları</summary>
<div class="admin-dropdown-content">
<div class="admin-subsection admin-subsection-tight">
  <div class="admin-card-header">
    <h3>// genel board banner ayarları</h3>
    <p>Dönüşüm zamanlamasını ve banner tıklamalarının siteden çıkmasına izin verilip verilmediğini yönetin.</p>
  </div>
  <form method="POST" action="/admin/site/settings" class="admin-site-settings-form admin-banner-settings-form">
    <input type="hidden" name="_csrf" value="{csrf}">
    <div class="board-settings-grid admin-settings-grid">
      <label class="board-settings-field-compact" title="0, her yenilemede yeni bir banner seçmek demektir. 0’dan büyük değerler zamanlı dönüşüm uygular.">Bannerları şu sürede bir değiştir (dakika)
        <input type="number" name="banner_rotation_interval_minutes" value="{banner_rotation_interval_minutes}" min="0" max="43200"
               style="font-family:inherit">
      </label>
      <label class="admin-inline-checkbox admin-banner-settings-toggle">
        <input type="checkbox" name="banner_external_links_enabled" value="1"{banner_external_links_enabled_checked} data-banner-external-toggle>
        Uyarı sayfası gösterildikten sonra banner’ların harici siteleri açmasına izin ver
      </label>
    </div>
    <div class="board-settings-actions">
      <button type="submit">banner ayarlarını kaydet</button>
    </div>
  </form>
</div>

<div class="admin-subsection admin-subsection-tight" id="global-banners">
  <div class="admin-card-header">
    <h3>// genel board bannerları</h3>
    <p>Bu bannerlar, bir board kendi banner setini kullanmıyorsa board dizini ve katalog sayfalarında dönüşür.</p>
  </div>
  <p class="admin-meta-note">Tam 468x60 en boy oranı gerekir. En az 468x60, önerilen 936x120. Yüklemeler WebP’ye dönüştürülür.</p>
  {global_banner_upload_form}
  <div class="admin-banner-list">{global_banner_rows}</div>
</div>

<div class="admin-subsection admin-subsection-tight" id="home-banners">
  <div class="admin-card-header">
    <h3>// ana sayfa banner ayarları</h3>
    <p>Yalnızca ana sayfadaki MOTD, haber veya bakım duyuruları için bu ayrı banner alanını kullan.</p>
  </div>
  <p class="admin-meta-note">Tam 468x60 en boy oranı gerekir. En az 468x60, önerilen 936x120. Yüklemeler WebP’ye dönüştürülür.</p>
  {home_banner_upload_form}
  <div class="admin-banner-list">{home_banner_rows}</div>
</div>

<div class="admin-subsection">
  <div class="admin-card-header">
    <h3>// board görünüm geçersiz kılmaları</h3>
    <p>Board’e özel temalar, favicon geçersiz kılmaları ve board banner setleri rutin board kartlarının içinde değil, burada yönetilir.</p>
  </div>
  <div class="admin-board-cards">{board_appearance_cards}</div>
</div>
</div>
</details>
</section>

<section class="admin-section admin-section-collapsible" id="theme-catalog">
<details class="admin-dropdown" data-admin-dropdown-key="theme-catalog"{theme_catalog_open_attr}>
<summary><span>// temalar</span></summary>
<div class="admin-dropdown-content">
<details class="admin-dropdown theme-workbench-dropdown" data-admin-dropdown-key="theme-workbench">
<summary><span>// özel tema atölyesi</span></summary>
<div class="admin-dropdown-content">
<div class="theme-manager-shell">
  <section class="theme-guide-card">
    <div class="admin-card-header">
      <h3>// rehberli tema oluşturucu</h3>
      <p>Kullanıcı dostu kontroller, eşleşen hex alanları ve temsilî bir önizlemeyle özel tema oluştur. TurkChan sonucu yine sunucuda oluşturulan normal CSS olarak kaydeder.</p>
    </div>
    <div class="theme-guide-grid">
      <div class="theme-guide-block">
        <h4>Oluşturucu akışı</h4>
        <p>Bir hazır ayarla başla, gruplandırılmış kontrolleri ayarla, sonra özel temayı kaydet.</p>
      </div>
      <div class="theme-guide-block">
        <h4>Uyumluluk</h4>
        <p>Yerleşik temalar olduğu gibi kalır ve eski ham CSS temaları eski kipte düzenlenebilir olmayı sürdürür.</p>
      </div>
    </div>
    <p class="theme-guide-note">Elle CSS, ana oluşturucu kolay taranabilir kalsın diye Gelişmiş/eski CSS bölümünde açıkça ayrıldı.</p>
  </section>

  <section class="theme-create-card">
    <div class="admin-card-header">
      <h3>// özel tema oluştur</h3>
      <p>Bir hazır ayardan başla, kullanıcı dostu alanları değiştir; TurkChan kapsamlı tema CSS’ini kendi içinde üretsin.</p>
    </div>
    <form method="POST" action="/admin/theme/create" class="theme-create-form">
      <input type="hidden" name="_csrf" value="{csrf}">
      <div class="board-settings-grid">
        <label>Görünen ad<input type="text" name="display_name" maxlength="64" required></label>
        <label>Kısa ad<input type="text" name="slug" maxlength="32" required placeholder="kenditemam"></label>
        <label>Tema seçici renk örneği<input type="color" name="swatch_hex" value="#7ab84e"></label>
      </div>
      <div class="board-settings-grid" style="margin-top:0.65rem">
        <label>Açıklama<input type="text" name="description" maxlength="256" placeholder="Bu temayı farklı kılan ne?"></label>
      </div>
      <div class="board-settings-checks">
        <label><input type="checkbox" name="enabled" value="1" checked> Tema seçicide gösterilsin</label>
      </div>
      {starter_builder_form}
      <div class="board-settings-actions">
        <button type="submit">tema oluştur</button>
      </div>
    </form>
  </section>
</div>
</div>
</details>

<section class="theme-manager-group">
  <div class="theme-manager-group-header">
    <h3>// yerleşik temalar</h3>
    <p>Gelen temalardan hangilerinin seçicide görüneceğini aç/kapa.</p>
  </div>
  <div class="theme-card-grid">{builtin_theme_cards}</div>
</section>

<section class="theme-manager-group">
  <div class="theme-manager-group-header">
    <h3>// özel temalar</h3>
    <p>Rehberli temalar oluşturucuda yeniden açılır. Oluşturucu üstverisi olmayan eski temalar, eski gelişmiş CSS temaları olarak erişilebilir kalır.</p>
  </div>
  <div class="theme-card-grid">{custom_theme_cards_or_empty}</div>
</section>
</div>
</details>
</section>
</div>"##,
        csrf = escape_html(csrf_token),
        banner_rotation_interval_minutes = banner_rotation_interval_minutes,
        banner_external_links_enabled_checked = banner_external_links_enabled_checked,
        banner_settings_open_attr = banner_settings_open_attr,
        global_banner_upload_form = global_banner_upload_form,
        global_banner_rows = global_banner_rows,
        home_banner_upload_form = home_banner_upload_form,
        home_banner_rows = home_banner_rows,
        board_appearance_cards = board_appearance_cards,
        theme_catalog_open_attr = theme_catalog_open_attr,
        builtin_theme_cards = builtin_theme_cards,
        custom_theme_cards_or_empty = custom_theme_cards_or_empty,
        starter_builder_form = render_builder_editor("new-theme-preview", &starter_builder),
    )
}
