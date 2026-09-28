//! Voting on posts.
//!
//! A vote is a one-press action a reader takes while looking at a post, so it
//! answers with a redirect back to exactly where the press happened rather than
//! with a new page. The buttons are real forms, so a reader with scripting off
//! gets the same behaviour, only slower because the page is re-rendered.

use crate::config::CONFIG;
use crate::db;
use crate::error::{AppError, Result};
use crate::middleware::AppState;
use axum::extract::{Form, State};
use axum::http::HeaderMap;
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

/// Resolve who is voting, without ever storing a raw address.
///
/// A signed-in account is keyed by its own row, so it can always take its vote
/// back. Anyone else is keyed by the same hashed identity the board already
/// uses for bans, so one person behind one address still gets one vote and no
/// address is kept. Tor exits and the loopback visitor cookie are folded into
/// that key first, so neither an exit nor a shared machine hands out extra
/// votes by accident.
fn voter_for(state: &AppState, jar: &CookieJar, client_ip: &str) -> Result<Option<String>> {
    if let Some(user_id) = crate::handlers::auth::current_account_id(state, jar)? {
        return Ok(db::voter_key(Some(user_id), None));
    }
    let identity = crate::handlers::board::identity_key(client_ip, jar);
    let hash = crate::utils::crypto::hash_ip(&identity, &CONFIG.cookie_secret);
    Ok(db::voter_key(None, Some(&hash)))
}

// POST /vote
pub(in crate::server) async fn cast_vote(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    crate::middleware::ClientIp(client_ip): crate::middleware::ClientIp,
    Form(form): Form<VoteForm>,
) -> Result<Response> {
    crate::handlers::board::check_csrf_jar(&jar, form.csrf.as_deref())?;
    let back = strict_safe_internal_path_or(form.return_to.as_deref(), "/").to_owned();

    let voter = voter_for(&state, &jar, &client_ip)?
        .ok_or_else(|| AppError::Forbidden("Oylamak için giriş yapmalısın.".into()))?;

    let pool = state.db.clone();
    let post_id = form.post_id;
    let value = form.value;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        db::cast_vote(&conn, post_id, &voter, value)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))??;

    Ok(Redirect::to(back.as_str()).into_response())
}

#[cfg(test)]
/// The tests are about which identity a vote is recorded under, because that is
/// the part a reader cannot see: whether one person can hold two, and whether
/// signing in changes who a press belongs to.
mod tests {
    use super::voter_for;
    use crate::db;
    use crate::middleware::AppState;
    use anyhow::Result;
    use axum_extra::extract::cookie::{Cookie, CookieJar};

    /// A state whose database already holds one account, so "signed in" and
    /// "anonymous" are two different things rather than one.
    fn state_with_account() -> Result<(AppState, i64)> {
        let state = crate::test_fixtures::app_state();
        let pool = state.db.clone();
        let conn = pool.get()?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let user_id = db::create_user(&conn, "anon", "Anonim", &hash, None, "")?;
        Ok((state, user_id))
    }

    /// A jar carrying the account's session cookie.
    fn signed_in_jar(session_id: &str) -> CookieJar {
        let mut jar = CookieJar::new();
        jar.add(
            Cookie::build((crate::handlers::auth::USER_SESSION_COOKIE, session_id.to_owned()))
                .path("/")
                .build(),
        );
        jar
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A signed-in account votes under its own row, so it can always take the
    /// vote back even when it shares an address with other readers, and
    /// signing out changes whose vote the next press is. An anonymous visitor
    /// is still able to vote, keyed by the same hashed identity the board uses
    /// for bans rather than by the raw address.
    fn a_signed_in_account_votes_under_its_own_row() -> Result<()> {
        let (state, user_id) = state_with_account()?;
        let pool = state.db.clone();
        let conn = pool.get()?;
        let session_id = "session-under-test";
        db::create_user_session(&conn, session_id, user_id, i64::MAX)?;

        let anonymous = voter_for(&state, &CookieJar::new(), "10.0.0.1")?
            .ok_or_else(|| anyhow::anyhow!("an anonymous visitor must still be able to vote"))?;
        assert!(
            anonymous.starts_with("i:"),
            "an anonymous visitor is keyed by the hashed address: {anonymous}"
        );

        let account = voter_for(&state, &signed_in_jar(session_id), "10.0.0.1")?
            .ok_or_else(|| anyhow::anyhow!("a signed-in account must be able to vote"))?;
        assert_eq!(
            account,
            format!("u:{user_id}"),
            "a signed-in account is keyed by its own row, not by its address"
        );
        assert_ne!(
            account, anonymous,
            "the same reader signed in and signed out must not land on the same key"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// One address is one anonymous voter. Without this, a shared machine or a
    /// Tor exit would hand out one vote per reader behind it.
    fn one_address_is_one_anonymous_voter() -> Result<()> {
        let (state, _) = state_with_account()?;
        let first = voter_for(&state, &CookieJar::new(), "10.0.0.1")?
            .ok_or_else(|| anyhow::anyhow!("an anonymous visitor must be able to vote"))?;
        let again = voter_for(&state, &CookieJar::new(), "10.0.0.1")?
            .ok_or_else(|| anyhow::anyhow!("an anonymous visitor must be able to vote"))?;
        let other = voter_for(&state, &CookieJar::new(), "10.0.0.2")?
            .ok_or_else(|| anyhow::anyhow!("an anonymous visitor must be able to vote"))?;
        assert_eq!(first, again, "the same address must produce the same key");
        assert_ne!(first, other, "a different address must produce a different key");
        assert!(
            !first.contains("10.0.0.1"),
            "the key must not carry the raw address: {first}"
        );
        Ok(())
    }
}
