//! Voting on posts.
//!
//! A vote belongs to an account. A visitor without one is refused in words
//! rather than being counted by address: a score is a claim that a person made
//! about a post, and a hashed address is not a person -- it is a shared machine,
//! a Tor exit, or a room with one router, and every one of those would hand out
//! votes nobody cast.
//!
//! A vote is a one-press action a reader takes while looking at a post, so it
//! answers with a redirect back to exactly where the press happened rather than
//! with a new page. The buttons are real forms, so a reader with scripting off
//! gets the same behaviour, only slower because the page is re-rendered.

use crate::db;
use crate::error::{AppError, Result};
use crate::middleware::AppState;
use axum::extract::{Form, State};
use axum::response::{IntoResponse as _, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::utils::redirect::strict_safe_internal_path_or;

/// Form fields submitted by a vote button.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct VoteForm {
    /// Post being voted on.
    post_id: i64,
    /// `1` for an upvote, `-1` for a downvote, `0` to take the vote back.
    value: i64,
    /// Where the press happened, so the reader lands back on the post.
    return_to: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

// POST /post-vote
pub(in crate::server) async fn cast_vote(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<VoteForm>,
) -> Result<Response> {
    crate::handlers::board::check_csrf_jar(&jar, form.csrf.as_deref())?;
    let back = strict_safe_internal_path_or(form.return_to.as_deref(), "/").to_owned();

    // The sign-in check is separate so it can say what is actually wrong, and
    // the account is then resolved by the same rule writing follows: a
    // suspended account keeps its session and can still read the site, so it
    // is told it may not vote for the same reason it is told it may not post.
    if crate::handlers::auth::current_account_id(&state, &jar)?.is_none() {
        return Err(AppError::Forbidden("Oy vermek için giriş yapmalısın.".into()));
    }
    let voter = crate::handlers::auth::posting_account_id(&state, &jar)?;

    let pool = state.db.clone();
    let post_id = form.post_id;
    let value = form.value;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        db::cast_vote(&conn, post_id, voter, value)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    Ok(Redirect::to(back.as_str()).into_response())
}
