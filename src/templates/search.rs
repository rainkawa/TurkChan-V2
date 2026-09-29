//! The global search page.
//!
//! One box and one set of optional filters. A reader who knows only a word
//! presses enter and gets everything; a reader who remembers more narrows with
//! the filters underneath, and every filter left alone narrows nothing.
//!
//! The four kinds are shown in one list rather than in four tabs, because a
//! reader searching for a word does not know in advance whether the thing they
//! remember is a post, a thread, a board, or a person, and making them guess
//! before they have seen any results is how a search goes unused.

use std::fmt::Write as _;

use crate::db::search::{SearchHit, SearchKind};
use crate::models::Board;
use crate::utils::sanitize::escape_html;

use super::{urlencoding_simple, Pagination, UserPreferences};

/// Results shown per kind before the count is elided.
const MAX_HITS_PER_KIND: usize = 20;

/// Which filters the reader set, as the form needs them back.
#[derive(Debug, Clone, Default)]
pub struct SearchFormState {
    /// Only this board.
    pub board_short: String,
    /// Only this account's login name.
    pub user: String,
    /// Only on or after this day.
    pub since: String,
    /// Only before this day.
    pub until: String,
    /// `1` for only posts with media, `0` for only posts without, blank for
    /// either.
    pub media: String,
    /// At least this score.
    pub min_score: String,
    /// `1` for only opening posts, `0` for only replies, blank for either.
    pub op_only: String,
}

/// Render the global search page.
pub fn search_page(
    query: &str,
    state: &SearchFormState,
    posts: &[SearchHit],
    threads: &[SearchHit],
    boards: &[SearchHit],
    users: &[SearchHit],
    total: i64,
    page_number: i64,
    per_page: i64,
    all_boards: &[Board],
    current_theme: Option<&str>,
    preferences: UserPreferences,
) -> String {
    let mut body = format!(
        r#"<div class="page-box global-search-page">
<h2 class="global-search-title">Ara</h2>
<form method="GET" action="/search" class="search-form global-search-form">
  <label class="catalog-sort-label" for="global-search-input">Sorgu:</label>
  <input id="global-search-input" type="text" name="q" value="{query}" maxlength="200">
  <details class="global-search-filters">
    <summary>gelişmiş filtreler</summary>
    <label for="filter-board">Board</label>
    <select id="filter-board" name="board">
      <option value="">hepsi</option>
{board_options}
    </select>
    <label for="filter-user">Kullanıcı</label>
    <input id="filter-user" type="text" name="user" value="{user}" maxlength="64">
    <label for="filter-since">Tarih (başlangıç)</label>
    <input id="filter-since" type="date" name="since" value="{since}">
    <label for="filter-until">Tarih (bitiş)</label>
    <input id="filter-until" type="date" name="until" value="{until}">
    <label for="filter-media">Medya</label>
    <select id="filter-media" name="media">
      <option value="{media_any}">fark etmez</option>
      <option value="1"{media_yes_selected}>medyalı</option>
      <option value="0"{media_no_selected}>medyasız</option>
    </select>
    <label for="filter-score">En az oy</label>
    <input id="filter-score" type="number" name="min_score" value="{min_score}" min="0">
    <label for="filter-op">Tür</label>
    <select id="filter-op" name="op_only">
      <option value="{op_any}>fark etmez</option>
      <option value="1"{op_yes_selected}>konu</option>
      <option value="0"{op_no_selected}>yanıt</option>
    </select>
  </details>
  <button type="submit">ara</button>
</form>"#,
        query = escape_html(query),
        board_options = board_options(state, all_boards),
        user = escape_html(&state.user),
        since = escape_html(&state.since),
        until = escape_html(&state.until),
        media_any = if state.media.is_empty() { " selected" } else { "" },
        media_yes_selected = if state.media == "1" { " selected" } else { "" },
        media_no_selected = if state.media == "0" { " selected" } else { "" },
        min_score = escape_html(&state.min_score),
        op_any = if state.op_only.is_empty() { " selected" } else { "" },
        op_yes_selected = if state.op_only == "1" { " selected" } else { "" },
        op_no_selected = if state.op_only == "0" { " selected" } else { "" },
    );

    if query.trim().is_empty() {
        body.push_str(r#"<p class="global-search-empty">Ne aramak istediğini yaz.</p>"#);
    } else {
        let _ = write!(
            body,
            r#"<p class="global-search-summary">{} sonuç</p>"#,
            total
        );
        if posts.is_empty() && threads.is_empty() && boards.is_empty() && users.is_empty() {
            body.push_str(
                r#"<p class="global-search-empty">Sonuç bulunamadı. Farklı bir sözcük dene ya da filtreleri gevşet.</p>"#,
            );
        }
        body.push_str(&section("Yazılar", SearchKind::Post, posts));
        body.push_str(&section("Konular", SearchKind::Thread, threads));
        body.push_str(&section("Boardlar", SearchKind::Board, boards));
        body.push_str(&section("Kullanıcılar", SearchKind::User, users));

        let pagination = Pagination::new(page_number, per_page, total);
        if pagination.total_pages() > 1 {
            body.push_str(&super::render_pagination(
                &pagination,
                &format!("/search?q={}", urlencoding_simple(query)),
            ));
        }
    }
    body.push_str("</div>");

    super::base_layout_with_preferences(
        "Ara",
        None,
        &body,
        "",
        all_boards,
        current_theme,
        None,
        false,
        "/search",
        preferences,
    )
}

/// Render the board picker, with the reader's choice already made.
fn board_options(state: &SearchFormState, all_boards: &[Board]) -> String {
    let mut out = String::new();
    for board in all_boards {
        let _ = write!(
            out,
            r#"<option value="{short}"{selected}>{name}</option>"#,
            short = escape_html(&board.short_name),
            selected = if board.short_name == state.board_short {
                " selected"
            } else {
                ""
            },
            name = escape_html(&board.name),
        );
    }
    out
}

/// Render one group of results.
fn section(title: &str, kind: SearchKind, hits: &[SearchHit]) -> String {
    if hits.is_empty() {
        return String::new();
    }
    let mut out = format!(
        r#"<section class="global-search-section" data-kind="{kind}">
<h3 class="global-search-section-title">{title} ({count})</h3>
<ul class="global-search-results">"#,
        kind = kind.as_str(),
        title = escape_html(title),
        count = hits.len(),
    );
    for hit in hits.iter().take(MAX_HITS_PER_KIND) {
        let _ = write!(
            out,
            r#"<li class="global-search-result">
<a class="global-search-link" href="{href}">
<span class="global-search-result-title">{title}</span>
<span class="global-search-result-excerpt">{excerpt}</span>
</a>
</li>"#,
            href = escape_html(&hit.href),
            title = escape_html(&hit.title),
            excerpt = escape_html(&hit.excerpt),
        );
    }
    if hits.len() > MAX_HITS_PER_KIND {
        let _ = write!(
            out,
            r#"<li class="global-search-more">ve {} tane daha</li>"#,
            hits.len() - MAX_HITS_PER_KIND
        );
    }
    out.push_str("</ul></section>");
    out
}
