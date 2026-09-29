//! Global search, as a page.
//!
//! One route answers every search. A reader who knows a word and a reader who
//! remembers a board, a date range, and a person are both typing into the same
//! box; the difference is only which of the optional filters they filled in.
//!
//! Every filter arrives as a string and is turned into a bound value before it
//! reaches the database, and a filter that cannot be read as what it claims to
//! be is dropped rather than guessed at. A mistyped date costs the reader that
//! one narrowing, not the whole search.

use crate::db;
use crate::error::{AppError, Result};
use crate::middleware::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse as _, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::templates::search::{search_page, SearchFormState};

/// Post results shown on one page.
const POSTS_PER_PAGE: i64 = 20;

/// Results of each other kind shown alongside.
const AUX_PER_KIND: i64 = 20;

/// Query fields accepted by the search page.
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct GlobalSearchQuery {
    /// What the reader is looking for.
    pub q: Option<String>,
    /// Which page of the results.
    pub page: Option<i64>,
    /// Only this board, by its short name.
    pub board: Option<String>,
    /// Only this account, by its login name.
    pub user: Option<String>,
    /// Only on or after this day.
    pub since: Option<String>,
    /// Only before this day.
    pub until: Option<String>,
    /// `1` for only posts with media, `0` for only posts without.
    pub media: Option<String>,
    /// At least this score.
    pub min_score: Option<String>,
    /// `1` for only opening posts, `0` for only replies.
    pub op_only: Option<String>,
}

/// Read a whole number out of a filter box, or nothing.
///
/// A box holding a word, a sign, or a number too large to be a score narrows
/// nothing. Guessing at what was meant would be a search the reader did not
/// ask for, and silently ignoring it is a filter that did nothing while
/// looking like it did.
fn whole_number(raw: Option<&str>) -> Option<i64> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<i64>().ok()
}

/// Read a yes/no filter box, or nothing.
///
/// Only exactly `1` and `0` are an answer. Anything else — including a stray
/// space, which the reader may not even see — narrows nothing, because a
/// filter applied on a guess is a filter applied wrongly.
fn flag(raw: Option<&str>) -> Option<bool> {
    match raw?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

fn text_of(raw: Option<&String>) -> String {
    raw.map_or_else(String::new, |value| value.trim().to_owned())
}

/// GET /search — search everything.
pub(in crate::server) async fn global_search(
    State(state): State<AppState>,
    Query(q): Query<GlobalSearchQuery>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response> {
    let (jar, _csrf) = crate::handlers::board::ensure_csrf_for_request(
        jar,
        &headers,
        crate::handlers::board::optional_connect_info_peer(None),
    );
    let page = q.page.unwrap_or(1).max(1);
    let query = q.q.clone().unwrap_or_default();

    let html = tokio::task::spawn_blocking({
        let pool = state.db.clone();
        move || -> Result<String> {
            let conn = pool.get()?;
            let all_boards = crate::templates::live_boards();

            let board_short = text_of(q.board.as_ref());
            let board_id = if board_short.is_empty() {
                None
            } else {
                db::get_board_by_short(&conn, &board_short)?.map(|board| board.id)
            };
            let user = text_of(q.user.as_ref());
            let user_id = if user.is_empty() {
                None
            } else {
                db::find_user_by_username(&conn, &user)?.map(|account| account.id)
            };

            let filters = db::SearchFilters {
                board_id,
                user_id,
                since: db::parse_day(q.since.as_deref().unwrap_or_default(), false),
                until: db::parse_day(q.until.as_deref().unwrap_or_default(), true),
                has_media: flag(q.media.as_deref()),
                min_score: whole_number(q.min_score.as_deref()),
                op_only: flag(q.op_only.as_deref()),
            };

            let posts = db::global_search(
                &conn,
                &query,
                &filters,
                POSTS_PER_PAGE,
                (page - 1) * POSTS_PER_PAGE,
            )?;
            let total = db::count_global_search(&conn, &query, &filters)?;
            let threads = db::search_threads(&conn, &query, AUX_PER_KIND)?;
            let boards = db::search_boards(&conn, &query, AUX_PER_KIND)?;
            let users = db::search_users(&conn, &query, AUX_PER_KIND)?;

            Ok(search_page(
                &query,
                &SearchFormState {
                    board_short,
                    user,
                    since: text_of(q.since.as_ref()),
                    until: text_of(q.until.as_ref()),
                    media: text_of(q.media.as_ref()),
                    min_score: text_of(q.min_score.as_ref()),
                    op_only: text_of(q.op_only.as_ref()),
                },
                &posts,
                &threads,
                &boards,
                &users,
                total,
                page,
                POSTS_PER_PAGE,
                all_boards.as_ref(),
                None,
                crate::templates::UserPreferences::default(),
            ))
        }
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Search task failed: {error}")))??;

    Ok((jar, Html(html)).into_response())
}
