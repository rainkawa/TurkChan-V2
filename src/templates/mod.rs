//! Shared HTML rendering helpers and page fragments.

use crate::config::CONFIG;
use crate::models::{Board, Pagination, Theme, SEARCH_QUERY_MAX_CHARS};
use crate::utils::sanitize::escape_html;
use chrono::{Local, TimeZone as _};
use parking_lot::RwLock;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::UNIX_EPOCH;

/// Administrative page templates.
pub mod admin;
/// Registration and sign-in screens.
pub mod auth;
/// Board index, catalog, search, and archive templates.
pub mod board;
/// New-thread and reply form fragments.
pub mod forms;
/// Direct-message pages.
pub mod messages;
/// The notification centre.
pub mod notifications;
/// The global search page.
pub mod search;
/// Public account profile page.
pub mod profile;
/// Thread, post, poll, and self-service action templates.
pub mod thread;

pub use admin::*;
pub use auth::*;
pub use board::*;
pub use thread::*;

/// Selects the default page used by links to a board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredBoardView {
    /// Link directly to the board catalog.
    Catalog,
    /// Link directly to the paginated board index.
    Index,
}

impl PreferredBoardView {
    /// Returns whether board links should open the catalog.
    #[must_use]
    pub const fn is_catalog(self) -> bool {
        matches!(self, Self::Catalog)
    }
}

/// Rendering preferences stored for an individual visitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPreferences {
    /// Whether navigation omits boards marked not safe for work.
    pub hide_nsfw_boards: bool,
    /// Whether video and audio start muted.
    pub video_audio_muted: bool,
    /// The page opened by links to a board.
    pub preferred_board_view: PreferredBoardView,
    /// Whether new-thread and new-reply badges are rendered.
    pub show_activity_badges: bool,
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            hide_nsfw_boards: false,
            video_audio_muted: false,
            preferred_board_view: PreferredBoardView::Catalog,
            show_activity_badges: true,
        }
    }
}

impl UserPreferences {
    /// Encodes the preferences into a stable fragment for page `ETag` values.
    #[must_use]
    pub fn etag_fragment(self) -> String {
        format!(
            "u{}{}{}{}",
            i32::from(self.hide_nsfw_boards),
            i32::from(self.video_audio_muted),
            if self.preferred_board_view.is_catalog() {
                "c"
            } else {
                "i"
            },
            i32::from(self.show_activity_badges)
        )
    }
}

// Live site name (DB-overridable, falls back to CONFIG.forum_name)
// parking_lot::RwLock is used instead of std::sync::RwLock for two reasons:
//  1. It never poisons — no need to handle poisoned-lock errors on the hot path.
//  2. Arc<str> reduces the per-read allocation to a single atomic increment
//     instead of a full String::clone(), which matters under high concurrency.

/// Latest site name used by renderers that do not query the database.
static LIVE_SITE_NAME: LazyLock<RwLock<Arc<str>>> =
    LazyLock::new(|| RwLock::new(Arc::from(CONFIG.forum_name.as_str())));
/// Latest site subtitle used by renderers that do not query the database.
static LIVE_SITE_SUBTITLE: LazyLock<RwLock<Arc<str>>> =
    LazyLock::new(|| RwLock::new(Arc::from("select board to proceed")));

/// Invalidates cached selectors and theme assets when the theme catalog changes.
static LIVE_THEME_VERSION: AtomicU64 = AtomicU64::new(0);

/// Configured site default shared by renderers.
static LIVE_DEFAULT_THEME: LazyLock<RwLock<Arc<str>>> =
    LazyLock::new(|| RwLock::new(Arc::from("")));
/// Snapshot of themes currently available to page renderers.
#[expect(
    clippy::rc_buffer,
    reason = "the public live_themes API retains Arc<Vec<Theme>> for compatibility"
)]
static LIVE_THEMES: LazyLock<RwLock<Arc<Vec<Theme>>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Vec::new())));

/// In-memory cache of the current board list, used by standalone pages (error
/// pages, ban pages) that don't have DB access at render time.  Updated by
/// every handler that creates, deletes, or restores boards.
///
/// Stores a snapshot; stale for at most one request after a board change, but
/// that one request is itself the mutating POST which redirects anyway.
#[expect(
    clippy::rc_buffer,
    reason = "the public live_boards APIs retain Arc<Vec<Board>> for compatibility"
)]
static LIVE_BOARDS: LazyLock<RwLock<Arc<Vec<Board>>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Vec::new())));

/// Monotonically-increasing counter incremented every time the board list
/// changes.  Included in thread-page `ETags` so that adding or deleting a board
/// correctly invalidates cached thread pages (fixing stale nav bars).
static LIVE_BOARDS_VERSION: AtomicU64 = AtomicU64::new(0);
/// Cached default board navigation paired with its board-list version.
static LIVE_BOARD_NAV: LazyLock<RwLock<(u64, Arc<str>)>> =
    LazyLock::new(|| RwLock::new((0, Arc::from(""))));
/// Cache-busting version derived from the running executable.
static STATIC_ASSET_VERSION: LazyLock<String> = LazyLock::new(compute_static_asset_version);

/// Replace the in-memory board list.  Call after any board create / delete /
/// restore operation so that `error_page()` renders the correct top-bar links.
pub fn set_live_boards(boards: Vec<Board>) {
    *LIVE_BOARDS.write() = Arc::new(boards);
    // Thread-page ETags include this version so navigation changes invalidate them.
    LIVE_BOARDS_VERSION.fetch_add(1, Ordering::Relaxed);
    rebuild_live_board_nav();
}

/// Returns a shared snapshot of the live board list.
pub fn live_boards() -> Arc<Vec<Board>> {
    Arc::clone(&*LIVE_BOARDS.read())
}

/// Public snapshot of the live board list.
///
/// Used by the thread-updates handler to include current nav HTML in polling
/// responses so the JS can refresh the nav bar when boards change while a
/// thread is open.
pub fn live_boards_snapshot() -> Arc<Vec<Board>> {
    Arc::clone(&*LIVE_BOARDS.read())
}

/// Current board-list version.  Included in thread-page `ETags` so that board
/// mutations invalidate cached thread HTML (and thus stale nav bars).
pub fn live_boards_version() -> u64 {
    LIVE_BOARDS_VERSION.load(Ordering::Relaxed)
}

/// Computes the cache-busting version for static asset URLs.
fn compute_static_asset_version() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::metadata(path).ok())
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map_or_else(
            || env!("CARGO_PKG_VERSION").to_owned(),
            |duration| duration.as_secs().to_string(),
        )
}

#[must_use]
/// Appends the current cache-busting version to a static asset path.
pub fn static_asset_url(path: &str) -> String {
    format!("{path}?v={}", *STATIC_ASSET_VERSION)
}

#[must_use]
/// Returns whether a supplied static asset version is current.
pub fn static_asset_version_matches(version: &str) -> bool {
    version == STATIC_ASSET_VERSION.as_str()
}

/// Call this at startup (after first DB read) and after admin saves a new name.
pub fn set_live_site_name(name: &str) {
    let val: Arc<str> = if name.trim().is_empty() {
        Arc::from(CONFIG.forum_name.as_str())
    } else {
        Arc::from(name)
    };
    *LIVE_SITE_NAME.write() = val;
}

/// Updates the live subtitle, restoring its fallback when the value is blank.
pub fn set_live_site_subtitle(subtitle: &str) {
    let val: Arc<str> = if subtitle.trim().is_empty() {
        Arc::from("select board to proceed")
    } else {
        Arc::from(subtitle)
    };
    *LIVE_SITE_SUBTITLE.write() = val;
}

/// Update the in-memory default theme cache.
/// Pass an empty string to clear the admin override and fall back to the hard default.
pub fn set_live_default_theme(theme: &str) {
    *LIVE_DEFAULT_THEME.write() = Arc::from(theme);
    LIVE_THEME_VERSION.fetch_add(1, Ordering::Relaxed);
}

/// Read the current live default theme slug.
pub fn live_default_theme() -> Arc<str> {
    Arc::clone(&*LIVE_DEFAULT_THEME.read())
}

/// Replaces the in-memory theme snapshot.
pub fn set_live_themes(themes: Vec<Theme>) {
    *LIVE_THEMES.write() = Arc::new(themes);
    LIVE_THEME_VERSION.fetch_add(1, Ordering::Relaxed);
}

/// Returns a shared snapshot of the live themes.
pub fn live_themes() -> Arc<Vec<Theme>> {
    Arc::clone(&*LIVE_THEMES.read())
}

/// Read the current live site name.
pub fn live_site_name() -> Arc<str> {
    Arc::clone(&*LIVE_SITE_NAME.read())
}

/// Reads the current live site subtitle.
pub fn live_site_subtitle() -> Arc<str> {
    Arc::clone(&*LIVE_SITE_SUBTITLE.read())
}

#[must_use]
/// Resolves a case-insensitive theme slug to its enabled canonical spelling.
pub fn normalize_theme_slug(theme: &str) -> Option<String> {
    theme_slug_in(&live_themes(), theme)
}

/// Resolve against a single catalog snapshot so a render cannot mix enablement states.
fn theme_slug_in(themes: &[Theme], slug: &str) -> Option<String> {
    themes
        .iter()
        .find(|candidate| candidate.enabled && candidate.slug.eq_ignore_ascii_case(slug.trim()))
        .map(|candidate| candidate.slug.clone())
}

/// Resolve board, site, and emergency defaults from the same catalog snapshot.
fn resolve_page_default_theme(
    themes: &[Theme],
    site_default: &str,
    board_default: Option<&str>,
) -> String {
    board_default
        .and_then(|slug| theme_slug_in(themes, slug))
        .or_else(|| theme_slug_in(themes, site_default))
        .or_else(|| theme_slug_in(themes, crate::theme::HARD_DEFAULT_THEME))
        .or_else(|| {
            themes
                .iter()
                .find(|theme| theme.enabled)
                .map(|theme| theme.slug.clone())
        })
        .unwrap_or_else(|| crate::theme::HARD_DEFAULT_THEME.to_owned())
}

#[must_use]
/// Produces the theme-dependent fragment used in page `ETag` values.
pub fn page_theme_etag_fragment(
    current_theme: Option<&str>,
    board_default_theme: Option<&str>,
) -> String {
    let themes = live_themes();
    let default_theme =
        resolve_page_default_theme(&themes, &live_default_theme(), board_default_theme);
    let active_theme = current_theme
        .and_then(|slug| theme_slug_in(&themes, slug))
        .unwrap_or_else(|| default_theme.clone());
    let state = format!(
        "{active_theme}:{default_theme}:{}:{}",
        LIVE_THEME_VERSION.load(Ordering::Relaxed),
        *STATIC_ASSET_VERSION
    );
    crate::utils::crypto::sha256_hex(state.as_bytes())
        .chars()
        .take(12)
        .collect()
}

/// Builds the versioned stylesheet URL for a theme.
fn theme_css_href(theme: &str) -> String {
    format!(
        "/theme-css/{}?v={}",
        escape_html(theme),
        *STATIC_ASSET_VERSION
    )
}

/// Partitions boards into safe-for-work and not-safe-for-work navigation groups.
fn board_nav_groups(boards: &[Board]) -> (Vec<&Board>, Vec<&Board>) {
    let sfw = boards
        .iter()
        .filter(|board| !board.nsfw)
        .collect::<Vec<_>>();
    let nsfw = boards.iter().filter(|board| board.nsfw).collect::<Vec<_>>();
    (sfw, nsfw)
}

/// Builds a board link honoring the visitor's preferred board view.
fn board_href(short_name: &str, preferences: UserPreferences) -> String {
    if preferences.preferred_board_view.is_catalog() {
        format!("/{}/catalog", escape_html(short_name))
    } else {
        format!("/{}", escape_html(short_name))
    }
}

/// Renders one board-navigation group when it is nonempty.
///
/// The links are emitted one per board with no separator between them: the rail
/// stacks them as a column of boards, so the reader sees one name per line
/// rather than the `[ a / b / c ]` run the markup used to carry.
fn board_nav_group_html(
    boards: &[&Board],
    preferences: UserPreferences,
    is_nsfw: bool,
    current: Option<&str>,
) -> Option<String> {
    if boards.is_empty() {
        return None;
    }
    let nsfw_attr = if is_nsfw {
        r#" data-board-nsfw="1""#
    } else {
        ""
    };
    let inner = boards
        .iter()
        .map(|board| {
            let active = current.is_some_and(|c| c.eq_ignore_ascii_case(&board.short_name));
            let current_attr = if active { r#" aria-current="page""# } else { "" };
            format!(
                r#"<a class="rail-board{active}" href="{href}"{current_attr}>/{short}/</a>"#,
                active = if active { " is-active" } else { "" },
                href = board_href(&board.short_name, preferences),
                current_attr = current_attr,
                short = escape_html(&board.short_name),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    Some(format!(r#"<span class="board-list-group"{nsfw_attr}>{inner}</span>"#))
}

/// Renders one mobile board-navigation group.
fn mobile_board_group_html(
    title: &str,
    boards: &[&Board],
    preferences: UserPreferences,
    is_nsfw: bool,
) -> String {
    if boards.is_empty() {
        return String::new();
    }
    let nsfw_attr = if is_nsfw {
        r#" data-board-nsfw="1""#
    } else {
        ""
    };
    let mut items = String::new();
    for board in boards {
        let short = escape_html(&board.short_name);
        let href = board_href(&board.short_name, preferences);
        let _ = write!(
            items,
            r#"<a class="mobile-board-link" href="{href}">/{short}/</a>"#,
        );
    }
    format!(
        r#"<div class="mobile-board-group"{nsfw_attr}><div class="mobile-board-group-title">{title}</div>{items}</div>"#
    )
}

/// Rebuilds the cached navigation for default visitor preferences.
fn rebuild_live_board_nav() {
    let boards = live_boards_snapshot();
    let nav_html = board_nav_html_for_preferences(boards.as_slice(), UserPreferences::default());
    let nav_html: Arc<str> = if nav_html.is_empty() {
        Arc::from("")
    } else {
        Arc::from(nav_html)
    };
    let version = live_boards_version();
    *LIVE_BOARD_NAV.write() = (version, nav_html);
}

#[must_use]
/// Renders board navigation using the supplied visitor preferences.
pub fn board_nav_html_for_preferences(boards: &[Board], preferences: UserPreferences) -> String {
    board_nav_html(boards, preferences, None)
}

#[must_use]
/// Renders board navigation, marking the board the reader is standing in.
pub fn board_nav_html_for_board(
    boards: &[Board],
    preferences: UserPreferences,
    current: Option<&str>,
) -> String {
    board_nav_html(boards, preferences, current)
}

/// Shared body of the two board-navigation renderers above.
fn board_nav_html(
    boards: &[Board],
    preferences: UserPreferences,
    current: Option<&str>,
) -> String {
    let (sfw_boards, nsfw_boards_all) = board_nav_groups(boards);
    let nsfw_boards = if preferences.hide_nsfw_boards {
        Vec::new()
    } else {
        nsfw_boards_all
    };
    [
        board_nav_group_html(&sfw_boards, preferences, false, current),
        board_nav_group_html(&nsfw_boards, preferences, true, current),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
}

/// Renders the mobile navigation items for initial pages and live thread updates.
pub(crate) fn mobile_board_nav_html_for_preferences(
    boards: &[Board],
    preferences: UserPreferences,
) -> String {
    let (sfw_boards, nsfw_boards) = board_nav_groups(boards);
    let mut items = mobile_board_group_html("Boards", &sfw_boards, preferences, false);
    if !preferences.hide_nsfw_boards {
        items.push_str(&mobile_board_group_html(
            "NSFW",
            &nsfw_boards,
            preferences,
            true,
        ));
    }
    items
}

// Auto-compress modal
/// Returns the compress-modal overlay HTML.
/// Dynamic size limits are embedded as data-max-image / data-max-video attributes
/// on the modal element and read by main.js at runtime ().
#[must_use]
pub fn compress_modal_script(max_image_bytes: usize, max_video_bytes: usize) -> String {
    format!(
        r#"
<div id="compress-modal" class="compress-modal" style="display:none" role="dialog" aria-modal="true" aria-labelledby="compress-modal-title" aria-hidden="true" hidden inert
     data-max-image="{max_image_bytes}" data-max-video="{max_video_bytes}">
  <div class="compress-modal-box">
    <div class="compress-modal-title" id="compress-modal-title">&#9888; Dosya Çok Büyük</div>
    <div class="compress-modal-info" id="compress-info"></div>
    <div class="compress-progress" id="compress-progress" style="display:none">
      <div class="compress-progress-track"><div class="compress-progress-bar" id="compress-progress-bar"></div></div>
      <div class="compress-progress-text" id="compress-progress-text">Hazırlanıyor…</div>
    </div>
    <div class="compress-modal-actions" id="compress-actions">
      <button class="compress-cancel-btn" data-action="dismiss-compress">Vazgeç</button>
      <button class="compress-do-btn" id="compress-do-btn" data-action="start-compress">&#9881; Otomatik Sıkıştır</button>
    </div>
    <div class="compress-done-actions" id="compress-done-actions" style="display:none">
      <button class="compress-cancel-btn" data-action="dismiss-compress">Kapat</button>
    </div>
  </div>
</div>"#,
    )
}

#[must_use]
/// Renders the reusable confirmation dialog.
pub const fn confirmation_modal_script() -> &'static str {
    r#"
<div id="confirm-modal" class="compress-modal" style="display:none" role="dialog" aria-modal="true" aria-labelledby="confirm-modal-title" aria-hidden="true" hidden inert>
  <div class="compress-modal-box confirm-modal-box">
    <div class="compress-modal-title" id="confirm-modal-title">İşlemi Onayla</div>
    <div class="compress-modal-info confirm-modal-info" id="confirm-modal-message"></div>
    <div class="compress-modal-actions">
      <button type="button" class="compress-cancel-btn" id="confirm-modal-cancel">Vazgeç</button>
      <button type="button" class="compress-do-btn" id="confirm-modal-continue">Devam Et</button>
    </div>
  </div>
</div>"#
}

#[must_use]
/// Renders the moderation dialog for banning an IP while deleting a post.
pub const fn admin_ban_delete_modal_script() -> &'static str {
    r#"
<div id="ban-delete-modal" class="compress-modal ban-delete-modal" style="display:none" role="dialog" aria-modal="true" aria-labelledby="ban-delete-modal-title" aria-describedby="ban-delete-modal-info" aria-hidden="true" hidden inert>
  <div class="compress-modal-box ban-delete-modal-box">
    <div class="compress-modal-title ban-delete-modal-title" id="ban-delete-modal-title">IP’yi Yasakla + Gönderiyi Sil</div>
    <form id="ban-delete-modal-form" novalidate>
      <div class="compress-modal-info confirm-modal-info ban-delete-modal-info" id="ban-delete-modal-info">
        Bu işlem, karma IP’yi yasaklar ve <strong id="ban-delete-post-label">No.</strong> gönderisini siler.
      </div>
      <div class="ban-delete-warning" role="note">Yıkıcı bir moderasyon işlemi. Vazgeçmek güvenlidir.</div>
      <div class="ban-delete-field">
        <label for="ban-delete-reason">Yasaklama sebebi</label>
        <input type="text" id="ban-delete-reason" maxlength="256" autocomplete="off" placeholder="Kural ihlali">
        <div class="ban-delete-help">Boş bırakırsan Kural ihlali kullanılır.</div>
      </div>
      <div class="ban-delete-field">
        <label for="ban-delete-duration">Süre (saat)</label>
        <input type="text" id="ban-delete-duration" inputmode="numeric" pattern="[0-9]*" value="0" autocomplete="off">
        <div class="ban-delete-help">Kalıcı yasaklama için 0 yaz.</div>
      </div>
      <div class="post-error-banner ban-delete-error" id="ban-delete-error" role="alert" hidden></div>
      <div class="compress-modal-actions ban-delete-actions">
        <button type="button" class="compress-cancel-btn" id="ban-delete-cancel">Cancel</button>
        <button type="submit" class="compress-do-btn btn-danger" id="ban-delete-submit">IP’yi Yasakla + Sil</button>
      </div>
    </form>
  </div>
</div>"#
}

// Report modal
/// Returns the report overlay HTML. Injected once per thread page.
// JS functions live in /static/main.js.
#[must_use]
pub const fn report_modal_script() -> &'static str {
    r#"
<div id="report-modal" class="compress-modal" style="display:none" role="dialog" aria-modal="true" aria-labelledby="report-modal-title" aria-describedby="report-info" aria-hidden="true" hidden inert>
  <div class="compress-modal-box">
    <div class="compress-modal-title" id="report-modal-title">Konu/Gönderi Şikayet Et</div>
    <form method="POST" action="/report" id="report-form">
      <input type="hidden" name="_csrf"     id="report-csrf">
      <input type="hidden" name="post_id"   id="report-post-id">
      <input type="hidden" name="thread_id" id="report-thread-id">
      <input type="hidden" name="board"     id="report-board">
      <input type="hidden" name="ip_hash"   id="report-ip-hash">
      <div class="compress-modal-info confirm-modal-info" id="report-info"></div>
      <label class="modal-field-label" for="report-reason">sebep</label>
      <input type="text" name="reason" id="report-reason"
             placeholder="sebep (isteğe bağlı)" maxlength="256"
             style="width:100%;background:var(--bg-input);border:1px solid var(--border);
                    color:var(--text);padding:8px 10px;font-family:var(--font);font-size:16px;
                    min-height:38px;
                    box-sizing:border-box;margin-bottom:0.75rem">
      <div class="compress-modal-actions">
        <button type="button" class="compress-cancel-btn" data-action="close-report">Vazgeç</button>
        <button type="submit" class="compress-do-btn" id="report-submit-btn">Şikayeti Gönder</button>
      </div>
    </form>
  </div>
</div>"#
}

#[must_use]
/// Renders the no-JavaScript report form used by report controls.
fn report_fallback_form(
    board_short: &str,
    post_id: i64,
    thread_id: i64,
    csrf_token: &str,
    submit_label: &str,
) -> String {
    format!(
        r#"<form class="report-fallback-form" method="POST" action="/report">
  <input type="hidden" name="_csrf" value="{csrf}">
  <input type="hidden" name="post_id" value="{post_id}">
  <input type="hidden" name="thread_id" value="{thread_id}">
  <input type="hidden" name="board" value="{board}">
  <details class="report-fallback-details">
    <summary class="report-fallback-summary">şikayet et</summary>
    <label class="report-fallback-reason-label">
      <span>sebep</span>
      <input class="report-fallback-reason" type="text" name="reason" maxlength="256" placeholder="sebep (isteğe bağlı)">
    </label>
    <button type="submit" class="report-fallback-submit">{submit_label}</button>
  </details>
</form>"#,
        csrf = escape_html(csrf_token),
        post_id = post_id,
        thread_id = thread_id,
        board = escape_html(board_short),
        submit_label = escape_html(submit_label),
    )
}

// Thread auto-update script
// All auto-update logic lives in /static/main.js.
#[must_use]
/// Renders the thread auto-update status controls.
pub const fn thread_autoupdate_script() -> &'static str {
    ""
}

// Timestamp helpers
#[must_use]
/// Formats a Unix timestamp in the server's local time.
pub fn fmt_ts(ts: i64) -> String {
    match Local.timestamp_opt(ts, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        _ => "unknown".to_owned(),
    }
}

#[must_use]
/// Formats a Unix timestamp as an RFC 3339 instant in UTC.
///
/// Used for the machine-readable `datetime` of a `<time>` element, where the
/// browser needs a value it can parse rather than one meant for a reader.
pub fn iso_timestamp(ts: i64) -> String {
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt.to_rfc3339(),
        None => String::new(),
    }
}

#[must_use]
/// Formats a Unix timestamp compactly in the server's local time.
pub fn fmt_ts_short(ts: i64) -> String {
    match Local.timestamp_opt(ts, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%m/%d/%y(%a)%H:%M:%S").to_string(),
        _ => "?".to_owned(),
    }
}

#[must_use]
/// Extracts the first supported embedded-media thumbnail URL from post text.
/// Used by catalog and board-index summaries when the OP has no uploaded file.
pub fn embed_thumb_from_body(body: &str) -> Option<String> {
    for token in body.split_whitespace() {
        let clean = token.trim_end_matches(['.', ',', ')', ';', '\'']);
        if let Some((embed_type, id)) = crate::utils::sanitize::extract_video_embed(clean) {
            if embed_type == "youtube" {
                return Some(format!("https://img.youtube.com/vi/{id}/mqdefault.jpg"));
            }
        }
    }
    None
}

// Pagination helper
#[must_use]
/// Renders previous and next links for a paginated collection.
pub fn render_pagination(p: &Pagination, base_url: &str) -> String {
    if p.total_pages() <= 1 {
        return String::new();
    }
    let sep = if base_url.contains('?') { "&" } else { "?" };
    // escape base_url once here so every href it appears in is safe,
    // regardless of what any caller passes.  All current callers pass trusted
    // values, but this makes the helper defensively correct for future callers.
    let safe_base = escape_html(base_url);
    let mut html = String::from(r#"<div class="pagination">"#);

    if p.has_prev() {
        let _ = write!(
            html,
            r#"<a href="{}{sep}page={}">[önceki]</a> "#,
            safe_base,
            p.page.saturating_sub(1),
            sep = sep
        );
    }
    let _ = write!(html, "sayfa {} / {}", p.page, p.total_pages());
    if p.has_next() {
        let _ = write!(
            html,
            r#" <a href="{}{sep}page={}">[sonraki]</a>"#,
            safe_base,
            p.page.saturating_add(1),
            sep = sep
        );
    }

    html.push_str("</div>");
    html
}

// Encode each UTF-8 *byte*, not each Unicode codepoint.
// RFC 3986 percent-encoding operates on bytes.
#[must_use]
/// Percent-encodes a string for use in a URL query component.
pub fn urlencoding_simple(s: &str) -> String {
    crate::utils::redirect::encode_form_query_component(s)
}

// Base layout
#[expect(
    clippy::too_many_arguments,
    reason = "the base layout accepts independent page metadata and rendering context"
)]
#[must_use]
/// Renders the shared document layout with default visitor preferences.
pub fn base_layout(
    title: &str,
    board_short: Option<&str>,
    body: &str,
    csrf_token: &str,
    boards: &[Board],
    current_theme: Option<&str>,
    board_default_theme: Option<&str>,
    collapse_greentext: bool,
    current_path: &str,
) -> String {
    base_layout_with_preferences(
        title,
        board_short,
        body,
        csrf_token,
        boards,
        current_theme,
        board_default_theme,
        collapse_greentext,
        current_path,
        UserPreferences::default(),
    )
}

#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "the base layout accepts independent page metadata and rendering context"
)]
/// Renders the shared document layout with explicit visitor preferences.
pub fn base_layout_with_preferences(
    title: &str,
    board_short: Option<&str>,
    body: &str,
    csrf_token: &str,
    boards: &[Board],
    current_theme: Option<&str>,
    board_default_theme: Option<&str>,
    collapse_greentext: bool,
    current_path: &str,
    preferences: UserPreferences,
) -> String {
    base_layout_with_account(
        title,
        board_short,
        body,
        csrf_token,
        boards,
        current_theme,
        board_default_theme,
        collapse_greentext,
        current_path,
        preferences,
        None,
        "",
    )
}

/// The mark drawn in the top bar's home button.
///
/// An icon rather than the word "Ana Sayfa": the button sits next to the brand,
/// which already links home, so the label repeated the thing the reader can
/// already see. It still carries the name for anyone who cannot see the shape.
const ICON_HOME: &str = r##"<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 3.2 2.6 11.1a1 1 0 0 0 .64 1.76H5v7.14a1 1 0 0 0 1 1h4.2v-5.1h3.6V21H18a1 1 0 0 0 1-1v-7.14h1.76a1 1 0 0 0 .64-1.76Z"/></svg>"##;

/// The mark drawn beside the "Yeni" entry.
const ICON_NEW: &str = r##"<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 2.4a9.6 9.6 0 1 0 9.6 9.6A9.61 9.61 0 0 0 12 2.4Zm1.06 4.66h-2.12v3.3H7.64v2.12h3.3v3.3h2.12v-3.3h3.3v-2.12h-3.3Z"/></svg>"##;

/// The mark drawn beside the "Popüler" entry.
const ICON_POPULAR: &str = r##"<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M13.5 1.5S13 5 10.6 7.2C8.5 9.1 6 10.6 6 14.1A6.4 6.4 0 0 0 12.4 20.5a6.4 6.4 0 0 0 6.4-6.4c0-3.2-2-4.6-3.3-6.3-.4 1-1.1 1.7-2 2.1.6-3.2 0-6.6 0-8.4Z"/></svg>"##;

/// The mark drawn beside the "Ara" entry.
const ICON_SEARCH: &str = r##"<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M10.4 2.6a7.8 7.8 0 1 0 4.72 13.94l4.4 4.4 1.5-1.5-4.4-4.4A7.8 7.8 0 0 0 10.4 2.6Zm0 2a5.8 5.8 0 1 1 0 11.6 5.8 5.8 0 0 1 0-11.6Z"/></svg>"##;

/// The mark in the bottom navigation's home slot.
const TAB_HOME: &str = r##"<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 3.2 2.6 11.1a1 1 0 0 0 .64 1.76H5v7.14a1 1 0 0 0 1 1h4.2v-5.1h3.6V21H18a1 1 0 0 0 1-1v-7.14h1.76a1 1 0 0 0 .64-1.76Z"/></svg>"##;

/// The mark in the bottom navigation's search slot.
const TAB_SEARCH: &str = r##"<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M10.4 2.6a7.8 7.8 0 1 0 4.72 13.94l4.4 4.4 1.5-1.5-4.4-4.4A7.8 7.8 0 0 0 10.4 2.6Zm0 2a5.8 5.8 0 1 1 0 11.6 5.8 5.8 0 0 1 0-11.6Z"/></svg>"##;

/// The mark in the bottom navigation's direct-message slot.
const TAB_MESSAGES: &str = r##"<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 2.6c-5.3 0-9.6 3.6-9.6 8.1 0 2.6 1.5 4.9 3.8 6.4l-.9 4.3 4.4-2.3a12.4 12.4 0 0 0 2.3.2c5.3 0 9.6-3.6 9.6-8.1S17.3 2.6 12 2.6Z"/></svg>"##;

/// The mark in the bottom navigation's notification slot.
const TAB_NOTIFICATIONS: &str = r##"<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 2.4a6.2 6.2 0 0 0-6.2 6.2v3.9L4 16.2a.8.8 0 0 0 .7 1.1h14.6a.8.8 0 0 0 .7-1.1l-1.8-3.7V8.6A6.2 6.2 0 0 0 12 2.4Zm-2.3 15.2a2.3 2.3 0 0 0 4.6 0Z"/></svg>"##;

/// Render the five slots of the bottom navigation, in their fixed order.
///
/// The order is the whole design: home, search, direct messages, notifications,
/// profile. Nothing that creates content sits in here — a thread is opened from
/// the bar at the top of the feed, and from the board it belongs to — because a
/// bar with a create button in it has nowhere to put the five places a reader
/// actually goes.
fn tab_bar_html(current_path: &str, account: Option<&AccountMenu>) -> String {
    // The sign-in and registration screens are the one place a signed-out
    // visitor lands, and every slot but "home" answers a signed-out visitor
    // with a refusal. A bar of five doors where four are locked is not a
    // navigation, so those two screens carry none.
    if current_path.starts_with("/login") || current_path.starts_with("/register") {
        return String::new();
    }
    let on = |prefix: &str| {
        if current_path == prefix || current_path.starts_with(&format!("{prefix}/")) {
            r#" is-active" aria-current="page"#
        } else {
            ""
        }
    };
    let profile_href = account.map_or_else(|| "/login".to_owned(), |account| {
        format!("/u/{}", escape_html(&account.username))
    });
    // The profile slot carries the reader's own picture when there is one, and
    // the first letter of a name when there is not: an empty circle reads as a
    // picture that failed to load rather than as a fallback.
    let profile_face = account.map_or_else(String::new, |account| match (account.user_id, &account.avatar_file) {
        (Some(user_id), Some(_)) => format!(
            r#"<img src="/auth/avatar/{user_id}?v={version}" alt="" width="24" height="24" loading="lazy" decoding="async">"#,
            version = escape_html(&avatar_version(account.avatar_file.as_deref())),
        ),
        _ => escape_html(&account_initial(
            &account.display_name,
            &account.username,
        )),
    });

    format!(
        r##"<nav class="tabbar" aria-label="Ana gezinme">
<a class="tabbar-item{home}" href="/"><span class="tabbar-icon">{home_icon}</span><span class="tabbar-label">Ana Sayfa</span></a>
<a class="tabbar-item{search}" href="/search"><span class="tabbar-icon">{search_icon}</span><span class="tabbar-label">Arama</span></a>
<a class="tabbar-item{messages}" href="/messages"><span class="tabbar-icon">{messages_icon}</span><span class="tabbar-badge" id="tabbar-messages-badge" data-unread="0" hidden>0</span><span class="tabbar-label">DM</span></a>
<a class="tabbar-item{notifications}" href="/notifications"><span class="tabbar-icon">{notifications_icon}</span><span class="tabbar-badge" id="tabbar-notifications-badge" data-unread="0" hidden>0</span><span class="tabbar-label">Bildirimler</span></a>
<a class="tabbar-item{profile}" href="{profile_href}"><span class="tabbar-icon tabbar-avatar">{profile_face}</span><span class="tabbar-label">Profil</span></a>
</nav>"##,
        home = on("/"),
        search = on("/search"),
        messages = on("/messages"),
        notifications = on("/notifications"),
        profile = if account.is_some() { on("/u/") } else { "" },
        home_icon = TAB_HOME,
        search_icon = TAB_SEARCH,
        messages_icon = TAB_MESSAGES,
        notifications_icon = TAB_NOTIFICATIONS,
        profile_href = profile_href,
        profile_face = profile_face,
    )
}

#[must_use]
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the shared layout keeps its HTML structure and page context together"
)]
/// Renders the shared document layout with a signed-in account menu.
///
/// `account` is the identity the page was rendered for, and the layout draws
/// both the header menu and the bottom navigation from it: the last slot of
/// that navigation is the reader's own profile, and a picture is served by
/// account row. A page that has no identity to offer passes `None`.
pub fn base_layout_with_account(
    title: &str,
    board_short: Option<&str>,
    body: &str,
    csrf_token: &str,
    boards: &[Board],
    current_theme: Option<&str>,
    board_default_theme: Option<&str>,
    collapse_greentext: bool,
    current_path: &str,
    preferences: UserPreferences,
    account: Option<&AccountMenu>,
    account_menu_csrf: &str,
) -> String {
    let account_menu_markup = account_menu_html(account, account_menu_csrf);
    let board_links = board_nav_html_for_board(boards, preferences, board_short);
    // The account menu is rendered only when somebody is signed in, so an
    // empty one is this layout's record of a signed-out visitor. The bar and the
    // rail both need it: the notification centre and the message list answer 403
    // to an anonymous visitor, and the rail's own entry used to point at
    // `/account/profile`, which is a POST target with no page behind it.
    let signed_in = account.is_some();
    let is_auth_page = current_path.starts_with("/login") || current_path.starts_with("/register");
    let topbar_account_links = if signed_in {
        r#"<span class="topbar-actions-divider" aria-hidden="true"></span>
      <a class="topbar-action" href="/notifications" title="Bildirimler">Bildirimler</a>
      <a class="topbar-action" href="/messages" title="Mesajlar">Mesajlar</a>"#
            .to_owned()
    } else if is_auth_page {
        String::new()
    } else {
        r#"<span class="topbar-actions-divider" aria-hidden="true"></span>
      <a class="topbar-action" href="/login" title="Giriş yap">Giriş Yap</a>
      <a class="topbar-action" href="/register" title="Kayıt ol">Kayıt Ol</a>"#
            .to_owned()
    };
    let rail_account_link = if signed_in {
        r#"<a class="rail-link rail-link-muted" href="/account/edit">Profilim</a>"#.to_owned()
    } else if is_auth_page {
        String::new()
    } else {
        r#"<a class="rail-link rail-link-muted" href="/login">Giriş Yap</a>"#.to_owned()
    };
    // The administration panel and the setup wizard lay their own panels out
    // across the full width, so they do not take the reading rail.
    let shell_class = if current_path.starts_with("/admin") || current_path.starts_with("/setup") {
        "shell is-wide"
    } else {
        "shell"
    };
    let board_menu = if boards.is_empty() {
        String::new()
    } else {
        let items = mobile_board_nav_html_for_preferences(boards, preferences);
        format!(
            r#"<details class="mobile-board-menu">
  <summary class="mobile-board-menu-btn" aria-label="Board menüsünü aç" aria-controls="mobile-board-menu-panel"><span class="mobile-board-menu-label">Boardlar</span></summary>
  <nav class="mobile-board-menu-panel" id="mobile-board-menu-panel">{items}</nav>
</details>"#
        )
    };

    // Inside a board the box searches that board, where the reader already is.
    // Anywhere else it searches everything, because a reader who is not
    // standing in a board has not said which one they meant.
    let search_bar = board_short.map_or_else(
        || {
            format!(
                r#"<form class="search-form" method="GET" action="/search">
<input type="text" name="q" aria-label="Sitede ara" placeholder="sitede ara…" maxlength="{max_len}">
<button type="submit">git</button>
</form>"#,
                max_len = SEARCH_QUERY_MAX_CHARS
            )
        },
        |b| {
            format!(
                r#"<form class="search-form" method="GET" action="/{b}/search">
<input type="text" name="q" aria-label="/{b}/ içinde ara" placeholder="/{b}/ içinde ara…" maxlength="{max_len}">
<button type="submit" formaction="/search">genel ara</button>
<button type="submit">git</button>
</form>"#,
                b = escape_html(b),
                max_len = SEARCH_QUERY_MAX_CHARS
            )
        },
    );

    let enabled_themes = live_themes();
    let enabled_theme_slugs = enabled_themes
        .iter()
        .filter(|theme| theme.enabled)
        .map(|theme| theme.slug.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let custom_theme_slugs = enabled_themes
        .iter()
        .filter(|theme| theme.enabled && !theme.is_builtin)
        .map(|theme| theme.slug.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let default_theme =
        resolve_page_default_theme(&enabled_themes, &live_default_theme(), board_default_theme);
    let active_theme = current_theme
        .and_then(|slug| theme_slug_in(&enabled_themes, slug))
        .unwrap_or_else(|| default_theme.clone());
    let default_theme_attr = format!(r#" data-default-theme="{}""#, escape_html(&default_theme));
    let theme_slugs_attr = format!(
        r#" data-theme-slugs="{}""#,
        escape_html(&enabled_theme_slugs)
    );
    let active_theme_attr = if active_theme == "terminal" {
        String::new()
    } else {
        format!(r#" data-theme="{}""#, escape_html(&active_theme))
    };
    let active_theme_value_attr = format!(r#" data-active-theme="{}""#, escape_html(&active_theme));
    let stylesheet_href = static_asset_url("/static/style.css");
    // The social layer is loaded last so it overrides the board's own layer
    // rather than the other way round: the two disagree on almost everything,
    // and which one wins must not depend on the order this file was written in.
    let social_stylesheet_href = static_asset_url("/static/social.css");
    let admin_stylesheet_href = static_asset_url("/static/admin.css");
    let theme_init_src = static_asset_url("/static/theme-init.js");
    let main_js_src = static_asset_url("/static/main.js");
    let admin_js_src = static_asset_url("/static/admin.js");
    let is_admin_page = current_path.starts_with("/admin");
    let uses_admin_styles = is_admin_page || current_path.starts_with("/setup");
    let theme_stylesheet_href = if crate::theme::builtin_theme(&active_theme).is_some() {
        String::new()
    } else {
        theme_css_href(&active_theme)
    };
    let theme_stylesheet_link = if crate::theme::builtin_theme(&active_theme).is_some() {
        String::new()
    } else {
        format!(
            r#"<link rel="stylesheet" id="active-theme-stylesheet" href="{theme_stylesheet_href}">"#
        )
    };
    let admin_stylesheet_link = if uses_admin_styles {
        format!(r#"<link rel="stylesheet" href="{admin_stylesheet_href}">"#)
    } else {
        String::new()
    };
    let admin_script_tag = if is_admin_page {
        format!(r#"<script src="{admin_js_src}" defer></script>"#)
    } else {
        String::new()
    };
    format!(
        r##"<!DOCTYPE html>
<html lang="tr" class="no-js" data-theme-css-slugs="{custom_theme_slugs}"{default_theme_attr}{theme_slugs_attr}{active_theme_value_attr}{active_theme_attr}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
{favicon_head}
<link rel="stylesheet" href="{stylesheet_href}">
<link rel="stylesheet" href="{social_stylesheet_href}">
{admin_stylesheet_link}
{theme_stylesheet_link}
<noscript><style>#post-form-wrap{{display:block!important}}</style></noscript>
<script src="{theme_init_src}"></script>
</head>
<body{collapse_attr}{tabbar_attr}>
<a class="skip-link" href="#main-content">&#8593; İçeriğe atla</a>
<header class="site-header">
  <div class="topbar">
    <a class="topbar-brand" href="/" aria-label="Ana sayfa">
      <span class="topbar-logo" aria-hidden="true">&#9679;</span>
      <span class="site-name">{forum_name}</span>
    </a>
    {board_menu}
    <div class="header-search topbar-search">{search_bar}</div>
    <nav class="topbar-actions" aria-label="Site gezinmesi">
      <a class="topbar-action topbar-action-home" href="/" title="Ana sayfa" aria-label="Ana sayfa">{home_icon}</a>
      <span class="topbar-actions-divider" aria-hidden="true"></span>
      <a class="topbar-action" href="/new" title="Yeni konular">{new_icon}<span>Yeni</span></a>
      <a class="topbar-action" href="/popular" title="Popüler konular">{popular_icon}<span>Popüler</span></a>
      <a class="topbar-action" href="/search" title="Ara">{search_icon}<span>Ara</span></a>
      {topbar_account_links}
    </nav>
    {account_menu_html}
    <div class="color-mode-switch" role="group" aria-label="Renk modu">
      <button type="button" class="color-mode-btn" data-action="set-color-mode" data-color-mode-value="light" aria-pressed="false" title="Aydınlık" aria-label="Aydınlık mod">&#9788;</button>
      <button type="button" class="color-mode-btn" data-action="set-color-mode" data-color-mode-value="dark" aria-pressed="false" title="Koyu" aria-label="Koyu mod">&#9789;</button>
      <button type="button" class="color-mode-btn" data-action="set-color-mode" data-color-mode-value="system" aria-pressed="false" title="Sistem" aria-label="Sistem modu">&#9881;</button>
    </div>
  </div>
</header>
<div class="{shell_class}">
<aside class="rail" aria-label="Boardlar ve gezinme">
  <nav class="rail-nav" aria-label="Keşfet">
    <a class="rail-link" href="/">Ana Sayfa</a>
    <a class="rail-link" href="/new">Yeni Konular</a>
    <a class="rail-link" href="/popular">Popüler</a>
    <a class="rail-link" href="/search">Ara</a>
  </nav>
  <h2 class="rail-title">Boardlar</h2>
  <nav class="board-list rail-boards">
    {board_links}
  </nav>
  <p class="rail-note">{site_tagline}</p>
  {rail_account_link}
</aside>
<main class="content" id="main-content">
{body}
</main>
</div>
<footer class="site-footer">
  <p class="site-footer-copy">{forum_name} &mdash; <a href="/">ana sayfa</a></p>
</footer>
{tab_bar}

{confirmation_modal}
<input type="hidden" id="csrf_global" value="{csrf_token}">
<script src="{main_js_src}" defer></script>
{admin_script_tag}
</body>
</html>"##,
        title = escape_html(title),
        favicon_head = crate::favicon::favicon_head_html(board_short),
        stylesheet_href = stylesheet_href,
        social_stylesheet_href = social_stylesheet_href,
        admin_stylesheet_link = admin_stylesheet_link,
        theme_stylesheet_link = theme_stylesheet_link,
        theme_init_src = theme_init_src,
        board_links = board_links,
        shell_class = shell_class,
        search_bar = search_bar,
        board_menu = board_menu,
        home_icon = ICON_HOME,
        new_icon = ICON_NEW,
        popular_icon = ICON_POPULAR,
        search_icon = ICON_SEARCH,
        topbar_account_links = topbar_account_links,
        rail_account_link = rail_account_link,
        account_menu_html = account_menu_markup,
        forum_name = escape_html(&live_site_name()),
        site_tagline = {
            // An empty configured subtitle would leave a stray line of space in
            // the header, so the brand keeps just its name in that case.
            let subtitle = live_site_subtitle();
            if subtitle.trim().is_empty() {
                String::new()
            } else {
                format!(
                    r#"<span class="site-tagline">{}</span>"#,
                    escape_html(subtitle.trim())
                )
            }
        },
        body = body,
        tab_bar = tab_bar_html(current_path, account),
        confirmation_modal = confirmation_modal_script(),
        csrf_token = escape_html(csrf_token),
        main_js_src = main_js_src,
        admin_script_tag = admin_script_tag,
        default_theme_attr = default_theme_attr,
        theme_slugs_attr = theme_slugs_attr,
        active_theme_value_attr = active_theme_value_attr,
        active_theme_attr = active_theme_attr,
        custom_theme_slugs = escape_html(&custom_theme_slugs),
        collapse_attr = if collapse_greentext {
            " data-collapse-greentext=\"1\""
        } else {
            ""
        },
        // The page reserves room for the bottom bar so the last card is not
        // left half under it. A screen that has no bar must not reserve room
        // for one, or the sign-in form floats a bar's height above the fold.
        tabbar_attr = if is_auth_page {
            " data-no-tabbar=\"1\""
        } else {
            ""
        },
    )
}

// Standalone error/ban pages (no board context)
// The appeal form must use the caller's CSRF token.
#[must_use]
/// Renders the standalone ban notice and appeal form.
pub fn ban_page(reason: &str, csrf_token: &str) -> String {
    ban_page_with_theme(reason, csrf_token, None, None)
}

/// Renders a ban notice with the request's validated theme preference.
pub(crate) fn ban_page_with_theme(
    reason: &str,
    csrf_token: &str,
    current_theme: Option<&str>,
    board_default: Option<&str>,
) -> String {
    let themes = live_themes();
    let enabled_theme_slugs = themes
        .iter()
        .filter(|theme| theme.enabled)
        .map(|theme| theme.slug.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let page_default = resolve_page_default_theme(&themes, &live_default_theme(), board_default);
    let configured_default = current_theme
        .and_then(|slug| theme_slug_in(&themes, slug))
        .unwrap_or_else(|| page_default.clone());
    let default_theme_attr = format!(r#" data-default-theme="{}""#, escape_html(&page_default));
    let theme_slugs_attr = format!(
        r#" data-theme-slugs="{}""#,
        escape_html(&enabled_theme_slugs)
    );
    let active_theme_attr = if configured_default == "terminal" {
        String::new()
    } else {
        format!(r#" data-theme="{}""#, escape_html(&configured_default))
    };
    let stylesheet_href = static_asset_url("/static/style.css");
    let social_stylesheet_href = static_asset_url("/static/social.css");
    let theme_init_src = static_asset_url("/static/theme-init.js");
    let main_js_src = static_asset_url("/static/main.js");
    let theme_stylesheet_link = if crate::theme::builtin_theme(&configured_default).is_some() {
        String::new()
    } else {
        format!(
            r#"<link rel="stylesheet" id="active-theme-stylesheet" href="{}">"#,
            theme_css_href(&configured_default)
        )
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="tr" class="no-js" data-active-theme="{active_theme}"{default_theme_attr}{theme_slugs_attr}{active_theme_attr}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Yasaklandınız</title>
<link rel="stylesheet" href="{stylesheet_href}">
<link rel="stylesheet" href="{social_stylesheet_href}">
{theme_stylesheet_link}
<script src="{theme_init_src}"></script>
</head>
<body>
<div class="page-box error-page">
<h1>yasaklandınız</h1>
<p style="color:var(--text-dim)">sebep: <strong>{reason}</strong></p>
<p style="margin-top:1.5rem;font-size:0.9rem">bu yasağın hatalı yapıldığını düşünüyorsan aşağıdan itiraz gönderebilirsin.<br>
itirazlar site yetkilileri tarafından incelenir. 24 saatte bir itiraz gönderebilirsin.</p>
<form method="POST" action="/appeal" class="appeal-form">
<input type="hidden" name="_csrf" id="appeal-csrf-field" value="{csrf}">
<textarea name="reason" rows="4" maxlength="512"
  placeholder="Bu yasağın kaldırılması gerektiğini düşündüğün nedeni kısaca açıkla…"
  style="width:100%;box-sizing:border-box;margin:0.75rem 0;background:var(--bg-post);color:var(--text);border:1px solid var(--border);padding:0.5rem;resize:none"></textarea>
<button type="submit" style="margin-top:0.25rem">itiraz gönder</button>
</form>
<p style="margin-top:1.5rem"><a href="/">ana sayfaya dön</a></p>
</div>
<input type="hidden" id="csrf_global" value="{csrf}">
<script src="{main_js_src}" defer></script>
</body>
</html>"#,
        default_theme_attr = default_theme_attr,
        theme_slugs_attr = theme_slugs_attr,
        active_theme_attr = active_theme_attr,
        stylesheet_href = stylesheet_href,
        social_stylesheet_href = social_stylesheet_href,
        theme_stylesheet_link = theme_stylesheet_link,
        theme_init_src = theme_init_src,
        active_theme = escape_html(&configured_default),
        reason = escape_html(reason),
        csrf = escape_html(csrf_token),
        main_js_src = main_js_src,
    )
}

#[must_use]
/// Renders a standalone error page using the shared site layout.
pub fn error_page(code: u16, message: &str) -> String {
    error_page_with_preferences(code, message, None, None, "", UserPreferences::default())
}

/// Renders the rate-limit notice with request preferences and its return hook.
#[must_use]
pub fn rate_limit_page_with_preferences(
    theme: Option<&str>,
    board_default: Option<&str>,
    csrf: &str,
    preferences: UserPreferences,
) -> String {
    let body = r#"<div class="page-box error-page">
<h1>Yavaş ol</h1><p>Çok hızlı geziniyorsun. Lütfen kısa süre sonra tekrar dene.</p>
<p><a href="/">ana sayfaya dön</a></p></div>"#;
    base_layout_with_preferences(
        "Yavaş ol",
        None,
        body,
        csrf,
        &live_boards(),
        theme,
        board_default,
        false,
        "/",
        preferences,
    )
    .replacen("<body", r#"<body data-rate-limit-page="1""#, 1)
}

/// Renders an error using the same preference precedence as the failed page.
pub(crate) fn error_page_with_preferences(
    code: u16,
    message: &str,
    current_theme: Option<&str>,
    board_default: Option<&str>,
    csrf: &str,
    preferences: UserPreferences,
) -> String {
    // Use base_layout so the error page has the same header, theme picker,
    // and board navigation as every other page.  live_boards() is always
    // up-to-date because every board mutation refreshes the cache.
    let boards = live_boards();
    let body = format!(
        r#"<div class="page-box error-page">
<h1>hata {code}</h1>
<p>{message}</p>
<p><a href="/">ana sayfaya dön</a></p>
</div>"#,
        code = code,
        message = escape_html(message),
    );
    base_layout_with_preferences(
        &format!("Hata {code}"),
        None,
        &body,
        csrf,
        &boards,
        current_theme,
        board_default,
        false,
        "/",
        preferences,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        base_layout, base_layout_with_account, base_layout_with_preferences, fmt_ts, fmt_ts_short,
        set_live_default_theme, set_live_themes, PreferredBoardView, UserPreferences,
    };
    use crate::models::{Board, Theme};

    fn builtin_theme(slug: &str, display_name: &str, sort_order: i64) -> Theme {
        Theme {
            slug: slug.to_owned(),
            display_name: display_name.to_owned(),
            description: format!("{display_name} description"),
            swatch_hex: "#123456".to_owned(),
            enabled: true,
            sort_order,
            is_builtin: true,
            custom_css: String::new(),
        }
    }

    #[test]
    fn theme_default_precedence_rejects_disabled_terminal_and_stale_slugs() {
        let mut terminal = builtin_theme("terminal", "Terminal", 1);
        terminal.enabled = false;
        let themes = vec![
            terminal,
            builtin_theme("forest", "Forest", 2),
            builtin_theme("blue-sky", "Blue Sky", 3),
        ];
        assert_eq!(
            super::resolve_page_default_theme(&themes, "blue-sky", Some("terminal")),
            "blue-sky"
        );
        assert_eq!(
            super::resolve_page_default_theme(&themes, "terminal", Some("deleted")),
            "forest"
        );
        assert_eq!(
            super::resolve_page_default_theme(&themes, "forest", Some(" BLUE-SKY ")),
            "blue-sky"
        );
        assert_eq!(
            super::resolve_page_default_theme(&[], "deleted", None),
            "forest"
        );
    }

    #[test]
    fn theme_normalization_only_accepts_enabled_exact_slugs() {
        let themes = vec![builtin_theme("forest", "Forest", 1)];
        assert_eq!(
            super::theme_slug_in(&themes, " FOREST "),
            Some("forest".into())
        );
        for slug in ["forest/..", "forest;", "<forest>", "deleted", ""] {
            assert_eq!(super::theme_slug_in(&themes, slug), None);
        }
    }

    #[test]
    fn base_layout_uses_forest_default_and_featured_theme_order() {
        set_live_default_theme("forest");
        set_live_themes(vec![
            builtin_theme("forest", "Forest", 10),
            builtin_theme("blue-sky", "Blue Sky", 20),
            builtin_theme("deep-orbit", "Deep Orbit", 30),
            builtin_theme("terminal", "Terminal", 40),
            builtin_theme("dorfic", "DORFic", 50),
        ]);

        let html = base_layout("Home", None, "<p>body</p>", "", &[], None, None, false, "/");

        assert!(html.contains(r#"data-default-theme="forest""#));
        // The enabled themes reach the browser as one ordered attribute, which
        // is what the pre-paint script reads; the footer select that used to
        // list them is gone.
        assert!(html.contains(r#"data-theme-slugs="forest,blue-sky,deep-orbit,terminal,dorfic""#));
    }

    #[test]
    fn base_layout_carries_the_active_theme_without_a_footer_preferences_panel() {
        set_live_default_theme("forest");
        set_live_themes(vec![
            builtin_theme("forest", "Forest", 10),
            builtin_theme("blue-sky", "Blue Sky", 20),
        ]);
        let preferences = UserPreferences {
            hide_nsfw_boards: true,
            video_audio_muted: true,
            preferred_board_view: PreferredBoardView::Index,
            show_activity_badges: false,
        };

        let html = base_layout_with_preferences(
            "Home",
            None,
            "<p>body</p>",
            "csrf",
            &[],
            Some("blue-sky"),
            None,
            false,
            "/",
            preferences,
        );

        // The theme the visitor picked is still what the page renders with, so
        // the pre-paint script and the colour variables agree.
        assert!(html.contains(r#"data-active-theme="blue-sky""#));
        assert!(html.contains(r#"data-theme="blue-sky""#));
        assert!(html.contains(r#"data-theme-slugs="forest,blue-sky""#));
        // The preferences sheet is gone from the footer. The colour switch in
        // the bar is what a visitor still chooses light or dark with.
        assert!(html.contains(r#"data-action="set-color-mode""#));
        assert!(!html.contains(r#"class="user-preferences-panel""#));
        assert!(!html.contains(r#"action="/preferences""#));
        // The bar is one row of marks rather than a line of words.
        assert!(html.contains(r#"class="topbar-action topbar-action-home""#));
        assert!(html.contains(r#"aria-label="Ana sayfa""#));
        assert!(html.contains("<span>Yeni</span>"));
        assert!(!html.contains(">Ana Sayfa</a>"));
        assert!(!html.contains(r#"class="admin-header-link""#));
        assert!(!html.contains(r#"class="admin-footer-link""#));
        assert!(!html.contains(r#"aria-label="Yönetici girişi""#));
    }

    #[test]
    fn setup_layout_loads_admin_styles_without_admin_javascript() {
        let html = base_layout(
            "setup",
            None,
            r#"<main class="setup-wizard"></main>"#,
            "csrf",
            &[],
            None,
            None,
            false,
            "/setup",
        );

        assert!(html.contains("/static/admin.css?v="));
        assert!(!html.contains("/static/admin.js?v="));
    }

    #[test]
    /// The social layer is linked from the shared layout, after the board's own
    /// stylesheet, because it is an override and an override loaded first is an
    /// override that never applies.
    fn the_layout_links_the_social_layer_after_the_board_stylesheet() {
        let html = base_layout("Home", None, "<p>body</p>", "", &[], None, None, false, "/");

        let board_sheet = html.find("/static/style.css").unwrap_or(usize::MAX);
        let social_sheet = html.find("/static/social.css").unwrap_or(0);
        assert!(social_sheet > board_sheet, "the layer has to come second: {html}");
        assert!(html.contains("/static/social.css?v="));
    }

    #[test]
    fn base_layout_hides_nsfw_nav_and_uses_index_links_when_requested() {
        let sfw = Board {
            short_name: "tech".into(),
            nsfw: false,
            ..crate::test_fixtures::sample_board()
        };
        let nsfw = Board {
            id: 2,
            short_name: "x".into(),
            nsfw: true,
            ..crate::test_fixtures::sample_board()
        };
        let preferences = UserPreferences {
            hide_nsfw_boards: true,
            preferred_board_view: PreferredBoardView::Index,
            ..UserPreferences::default()
        };

        let html = base_layout_with_preferences(
            "Home",
            None,
            "<p>body</p>",
            "csrf",
            &[sfw, nsfw],
            None,
            None,
            false,
            "/",
            preferences,
        );

        assert!(html.contains(r#"<a href="/tech">tech</a>"#));
        assert!(!html.contains(r#"<a href="/tech/catalog">tech</a>"#));
        assert!(!html.contains(r">x</a>"));
        assert!(html.contains(r#"class="mobile-board-link" href="/tech""#));
        assert!(!html.contains(r#"href="/x/catalog""#));
        assert!(!html.contains(r#"href="/x""#));
    }

    #[test]
    fn base_layout_marks_nsfw_nav_groups_for_client_preference_toggling() {
        let sfw = Board {
            short_name: "tech".into(),
            nsfw: false,
            ..crate::test_fixtures::sample_board()
        };
        let nsfw = Board {
            id: 2,
            short_name: "x".into(),
            nsfw: true,
            ..crate::test_fixtures::sample_board()
        };

        let html = base_layout_with_preferences(
            "Home",
            None,
            "<p>body</p>",
            "csrf",
            &[sfw, nsfw],
            Some("forest"),
            None,
            false,
            "/",
            UserPreferences::default(),
        );

        assert!(html.contains(r#"<span class="board-list-group" data-board-nsfw="1"><a class="rail-board" href="/x/catalog">/x/</a></span>"#));
        assert!(html.contains(r#"<div class="mobile-board-group" data-board-nsfw="1"><div class="mobile-board-group-title">NSFW</div><a class="mobile-board-link" href="/x/catalog">/x/</a></div>"#));
    }

    #[test]
    /// The bottom bar carries exactly five places, and their order is the
    /// design: home, search, messages, notifications, profile. Nothing that
    /// creates content sits in it, because a bar with a create button has no
    /// room left for the five places a reader actually goes.
    fn the_tab_bar_keeps_its_five_places_in_their_fixed_order() {
        set_live_default_theme("forest");
        set_live_themes(vec![builtin_theme("forest", "Forest", 10)]);
        let html = base_layout("Home", None, "<p>body</p>", "", &[], None, None, false, "/");

        let bar = html
            .split_once(r#"<nav class="tabbar""#)
            .and_then(|(_, rest)| rest.split_once("</nav>"))
            .map_or("", |(bar, _)| bar);
        let slots: Vec<&str> = ["Ana Sayfa", "Arama", "DM", "Bildirimler", "Profil"]
            .iter()
            .map(|label| {
                bar.find(label)
                    .map_or_else(|| usize::MAX, |position| position)
            })
            .collect();
        let mut sorted = slots.clone();
        sorted.sort_unstable();
        assert_eq!(
            slots, sorted,
            "the five slots appear in the order they are meant to be read: {bar}"
        );
        assert!(
            !bar.contains("Oluştur") && !bar.contains("Yeni Konu"),
            "content creation is not one of the five places: {bar}"
        );
        // Every slot leads somewhere that exists, so no tap lands on a refusal.
        for href in ["/", "/search", "/messages", "/notifications"] {
            assert!(bar.contains(&format!(r#"href="{href}""#)), "{href} is missing");
        }
    }

    #[test]
    /// The last slot carries the reader's own picture, and a name's first
    /// letter when there is no picture. An empty circle reads as an image that
    /// failed to load rather than as a fallback.
    fn the_tab_bar_profile_slot_carries_the_readers_own_picture() {
        set_live_default_theme("forest");
        set_live_themes(vec![builtin_theme("forest", "Forest", 10)]);
        let menu = crate::templates::auth::AccountMenu {
            display_name: "Mert".to_owned(),
            username: "rainkawa".to_owned(),
            is_admin: false,
            user_id: Some(7),
            avatar_file: Some("7-abc-0.png".to_owned()),
        };
        let html = base_layout_with_account(
            "Home",
            None,
            "<p>body</p>",
            "",
            &[],
            None,
            None,
            false,
            "/",
            UserPreferences::default(),
            Some(&menu),
            "csrf",
        );
        assert!(html.contains(r#"href="/u/rainkawa""#), "{html}");
        assert!(
            html.contains(&format!(
                r#"<img src="/auth/avatar/7?v={}""#,
                crate::templates::auth::avatar_version(Some("7-abc-0.png"))
            )),
            "the profile slot shows the picture the account uploaded"
        );
    }

    #[test]
    /// A signed-out visitor is sent to the sign-in screen from the profile
    /// slot rather than to a profile that does not exist yet.
    fn the_tab_bar_profile_slot_of_a_signed_out_visitor_leads_to_the_sign_in_screen() {
        set_live_default_theme("forest");
        set_live_themes(vec![builtin_theme("forest", "Forest", 10)]);
        let html = base_layout("Home", None, "<p>body</p>", "", &[], None, None, false, "/");
        let bar = html
            .split_once(r#"<nav class="tabbar""#)
            .and_then(|(_, rest)| rest.split_once("</nav>"))
            .map_or("", |(bar, _)| bar);
        assert!(bar.contains(r#"href="/login""#), "{bar}");
    }

    #[test]
    /// The sign-in and registration screens carry no bar. Every slot but home
    /// answers a signed-out visitor with a refusal, and four locked doors is
    /// not a navigation.
    fn the_sign_in_screens_carry_no_tab_bar() {
        set_live_default_theme("forest");
        set_live_themes(vec![builtin_theme("forest", "Forest", 10)]);
        for path in ["/login", "/register"] {
            let html = base_layout("Giriş", None, "<p>body</p>", "", &[], None, None, false, path);
            assert!(!html.contains(r#"<nav class="tabbar""#), "{path} has a bar");
            assert!(
                html.contains(r#"data-no-tabbar="1""#),
                "{path} must not reserve room for a bar it does not have"
            );
        }
    }

    #[test]
    fn timestamp_helpers_do_not_force_utc_suffix() {
        let full = fmt_ts(1_700_000_000);
        let short = fmt_ts_short(1_700_000_000);

        assert!(!full.contains("UTC"));
        assert!(!short.contains("UTC"));
        assert_ne!(full, "unknown");
        assert_ne!(short, "?");
    }

    #[test]
    fn timestamp_helpers_handle_out_of_range_epoch_values() {
        assert_eq!(fmt_ts(i64::MAX), "unknown");
        assert_eq!(fmt_ts_short(i64::MAX), "?");
    }
}
