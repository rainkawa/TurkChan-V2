//! Public profile page for an anonymous board account.
//!
//! The page is a read-only view of what an account already publishes on a
//! board: the chosen display name, the unique username, the self-description,
//! the join date, the accumulated score, and the account's own posts. Nothing
//! here adds or reveals identifying detail, and the same page is reachable for
//! any visitor who knows the username.

use std::collections::{HashMap, HashSet};

use super::{
    board_access_cookie_from_jar, can_view_board, current_theme_from_jar, db,
    ensure_csrf_for_request, optional_connect_info_peer, should_set_public_secure_cookie,
    user_preferences_from_jar, AppError, AppState, CookieJar, HeaderMap, Html,
    OptionalConnectInfoPeer, Path, Query, Response, Result, State,
};
use axum::response::IntoResponse as _;
use serde::Deserialize;

use crate::models::{
    Board, Pagination, ProfilePost, ProfilePostScope, ProfileStats, ProfileThread, User,
};
use crate::templates::profile::ProfileTab;
use crate::utils::sanitize::{escape_html, referenced_post_ids};

/// Records shown per profile tab page.
const PROFILE_ITEMS_PER_PAGE: i64 = 10;

/// Query parameters accepted by the profile page.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct ProfileQuery {
    /// Selected history tab.
    pub tab: Option<String>,
    /// One-based page number.
    pub page: Option<i64>,
}

/// Return the boards whose content this visitor is allowed to read.
///
/// A profile must never reveal a post from a board the visitor cannot open, so
/// the listing is filtered with the same rule the board index uses: a
/// password-protected board needs its unlock cookie, and an administrator sees
/// every board.
fn viewable_board_names(
    conn: &rusqlite::Connection,
    boards: &[Board],
    jar: &CookieJar,
    admin_session_id: Option<&str>,
) -> HashSet<String> {
    let is_admin = admin_session_id
        .is_some_and(|session_id| db::get_session(conn, session_id).ok().flatten().is_some());
    boards
        .iter()
        .filter(|board| {
            let access_cookie = board_access_cookie_from_jar(jar, &board.short_name);
            can_view_board(board, is_admin, access_cookie.as_deref())
        })
        .map(|board| board.short_name.clone())
        .collect()
}

/// Everything one profile page render needs, loaded on the blocking pool.
struct ProfileLoad {
    /// The account whose profile is shown.
    account: User,
    /// Activity totals for the header and the tab badges.
    stats: ProfileStats,
    /// Listed posts, empty on the threads tab.
    posts: Vec<ProfilePost>,
    /// Listed threads, empty on the other tabs.
    threads: Vec<ProfileThread>,
    /// Board short name for every post an excerpt references with `>>N`.
    referenced_boards: HashMap<i64, String>,
    /// Boards for the shared header navigation.
    boards: Vec<Board>,
    /// Paging state for the selected tab.
    pagination: Pagination,
}

pub(in crate::server) async fn profile(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(params): Query<ProfileQuery>,
    jar: CookieJar,
    req_headers: HeaderMap,
    peer: OptionalConnectInfoPeer,
) -> Result<Response> {
    let current_theme = current_theme_from_jar(&jar);
    let user_preferences = user_preferences_from_jar(&jar);
    let secure = should_set_public_secure_cookie(&req_headers, optional_connect_info_peer(peer));
    let (jar, csrf) = ensure_csrf_for_request(jar, &req_headers, optional_connect_info_peer(peer));

    // The shared layout carries the header account menu, whose sign-out control
    // needs the sign-in-scoped token, so that cookie is issued here as well.
    let identity = crate::handlers::auth::account_identity(&state, &jar)?;
    let (jar, menu_csrf) = if identity.is_some() {
        crate::handlers::auth::account_menu_csrf(jar, secure)
    } else {
        (jar, String::new())
    };
    // Bound before the reference is taken: the menu is passed to the layout
    // call far below, so the owned value has to outlive this statement.
    let menu = identity.map(|identity| crate::templates::auth::AccountMenu {
        display_name: identity.display_name,
        username: identity.username,
        is_admin: identity.is_admin,
    });
    let account_menu = menu.as_ref();

    let tab = ProfileTab::from_query(params.tab.as_deref());
    let page = params.page.unwrap_or(1).max(1);
    let offset = page
        .saturating_sub(1)
        .saturating_mul(PROFILE_ITEMS_PER_PAGE);
    // Usernames are stored trimmed and lower-cased, so the URL is matched the
    // same way the sign-in screen matches it.
    let username = username.trim().to_lowercase();

    let loaded = tokio::task::spawn_blocking({
        let pool = state.db.clone();
        let jar_for_visibility = jar.clone();
        let admin_session_id = jar
            .get(crate::handlers::board::ADMIN_SESSION_COOKIE)
            .map(|cookie| cookie.value().to_owned());
        move || -> Result<Option<ProfileLoad>> {
            let conn = pool.get()?;
            let Some(account) = db::find_user_by_username(&conn, &username)? else {
                return Ok(None);
            };
            let stats = db::profile_stats(&conn, account.id)?;
            let boards = db::get_all_boards(&conn)?;
            let viewable = viewable_board_names(
                &conn,
                &boards,
                &jar_for_visibility,
                admin_session_id.as_deref(),
            );
            let (mut posts, mut threads, total) = match tab {
                ProfileTab::Threads => (
                    Vec::new(),
                    db::list_profile_threads(&conn, account.id, PROFILE_ITEMS_PER_PAGE, offset)?,
                    stats.thread_count,
                ),
                ProfileTab::Posts => (
                    db::list_profile_posts(
                        &conn,
                        account.id,
                        ProfilePostScope::All,
                        PROFILE_ITEMS_PER_PAGE,
                        offset,
                    )?,
                    Vec::new(),
                    stats.post_count,
                ),
                ProfileTab::Replies => (
                    db::list_profile_posts(
                        &conn,
                        account.id,
                        ProfilePostScope::Replies,
                        PROFILE_ITEMS_PER_PAGE,
                        offset,
                    )?,
                    Vec::new(),
                    stats.reply_count,
                ),
            };

            // A post from a board this visitor cannot open stays off the page.
            posts.retain(|post| viewable.contains(&post.board_short));
            threads.retain(|thread| viewable.contains(&thread.board_short));

            // `>>N` names a post without naming its board, so the excerpts
            // resolve their references through one batched lookup.
            let mut referenced = Vec::new();
            for body in posts
                .iter()
                .map(|post| post.body.as_str())
                .chain(threads.iter().map(|thread| thread.body.as_str()))
            {
                referenced.extend(referenced_post_ids(&escape_html(body)));
            }
            let referenced_boards = db::resolve_post_boards(&conn, &referenced)?;

            Ok(Some(ProfileLoad {
                account,
                stats,
                posts,
                threads,
                referenced_boards,
                boards,
                pagination: Pagination::new(page, PROFILE_ITEMS_PER_PAGE, total),
            }))
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    let Some(loaded) = loaded else {
        return Err(AppError::NotFound("Böyle bir kullanıcı yok.".into()));
    };

    let html = crate::templates::profile::profile_page(
        &loaded.account,
        &loaded.stats,
        tab,
        &loaded.posts,
        &loaded.threads,
        &loaded.referenced_boards,
        &loaded.pagination,
        &loaded.boards,
        current_theme.as_deref(),
        user_preferences,
        &csrf,
        &crate::templates::auth::account_menu_html(account_menu, &menu_csrf),
    );

    let mut response = Html(html).into_response();
    // The account menu makes the page visitor-specific, so it must never be
    // reused from a shared cache without revalidating on the cookie.
    crate::cache::set_cache_control(
        response.headers_mut(),
        crate::cache::CACHE_CONTROL_DYNAMIC_PUBLIC,
    );
    crate::cache::insert_vary_cookie(response.headers_mut());
    Ok((jar, response).into_response())
}
