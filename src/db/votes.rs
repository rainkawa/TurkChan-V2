//! Post votes, and the account score they add up to.
//!
//! One row per post per voter is the whole model: the primary key is
//! `(post_id, voter_key)`, so "one vote per person" is a property of the
//! schema rather than something a handler has to remember to check. Casting a
//! vote is therefore an upsert, pressing the same arrow twice deletes the row,
//! and pressing the other one overwrites it — which is exactly the behaviour an
//! imageboard reader expects, and none of it needs a read-modify-write.
//!
//! The voter is identified by a *key* rather than by a foreign key alone, so
//! the same table serves both a signed-in account and an anonymous visitor. An
//! account is keyed by its row id and can therefore always remove its own
//! vote; an anonymous visitor is keyed by the hashed address already used for
//! bans, so nobody's raw address is stored and one person behind one address
//! still gets one vote.
//!
//! The score is never stored. It is the sum of a post's rows, and an account's
//! total is the base it started with plus the sum of the votes its posts
//! received — so a deleted post takes its votes with it and a score cannot
//! drift away from the votes that produced it.

use anyhow::{Context as _, Result};
use rusqlite::params;
use rusqlite::OptionalExtension as _;
use std::collections::HashMap;

use crate::roles::KARMASEED;

/// A vote as one post's score needs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PostVoteView {
    /// Sum of every vote on the post.
    pub score: i64,
    /// The viewer's own vote: `1`, `-1`, or `0` when they have not voted.
    pub my_vote: i64,
}

impl PostVoteView {
    /// Whether the viewer pressed the upvote on this post.
    #[must_use]
    pub fn upvoted(&self) -> bool {
        self.my_vote > 0
    }

    /// Whether the viewer pressed the downvote on this post.
    #[must_use]
    pub fn downvoted(&self) -> bool {
        self.my_vote < 0
    }
}

/// How an account's score is made up, as the profile shows it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KarmaBreakdown {
    /// Net votes the account's opening posts received.
    pub thread_likes: i64,
    /// Net votes the account's replies received.
    pub comment_likes: i64,
}

impl KarmaBreakdown {
    /// Votes received across every post the account wrote.
    #[must_use]
    pub const fn received(&self) -> i64 {
        self.thread_likes + self.comment_likes
    }

    /// The base the account started from.
    #[must_use]
    pub const fn base(&self) -> i64 {
        KARMASEED
    }

    /// The number the profile leads with.
    #[must_use]
    pub const fn total(&self) -> i64 {
        self.base() + self.received()
    }
}

/// Build the in-memory key for one voter.
///
/// The prefix keeps an account and an address from ever colliding, so an
/// account's votes cannot be removed by a visitor who happens to share the same
/// raw value.
#[must_use]
pub fn voter_key(user_id: Option<i64>, ip_hash: Option<&str>) -> Option<String> {
    match (user_id, ip_hash) {
        (Some(id), _) => Some(format!("u:{id}")),
        (None, Some(hash)) if !hash.is_empty() => Some(format!("i:{hash}")),
        _ => None,
    }
}

/// Apply a vote, or take it back.
///
/// Pressing the arrow that is already pressed removes the vote, which is why
/// `value` may be zero. The write is a single statement so two presses racing
/// cannot leave two rows behind.
///
/// The author's stored score is refreshed in the same breath, because that
/// column is what the account's trust tier and badge are decided from: a vote
/// that did not move it would leave a regular looking like a newcomer.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn cast_vote(
    conn: &rusqlite::Connection,
    post_id: i64,
    voter: &str,
    value: i64,
) -> Result<i64> {
    let value = value.clamp(-1, 1);
    if value == 0 {
        conn.execute(
            "DELETE FROM post_votes WHERE post_id = ?1 AND voter_key = ?2",
            params![post_id, voter],
        )
        .context("Failed to remove a post vote")?;
    } else {
        conn.execute(
            "INSERT INTO post_votes (post_id, voter_key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (post_id, voter_key) DO UPDATE SET value = excluded.value",
            params![post_id, voter, value],
        )
        .context("Failed to record a post vote")?;
    }
    if let Some(author_id) = post_author(conn, post_id)? {
        refresh_account_score(conn, author_id)?;
    }
    post_score(conn, post_id)
}

/// The account that wrote a post, when it is not an anonymous one.
fn post_author(conn: &rusqlite::Connection, post_id: i64) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT user_id FROM posts WHERE id = ?1",
        params![post_id],
        |row| row.get::<_, Option<i64>>(0),
    )
    .context("Failed to read a post's author")
}

/// Recompute one account's stored score from the votes its posts received.
///
/// The score is written, not incremented, so it cannot drift away from the
/// votes: taking a vote back moves the account back down exactly as far.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn refresh_account_score(conn: &rusqlite::Connection, user_id: i64) -> Result<i64> {
    let breakdown = karma_breakdown(conn, user_id)?;
    let total = breakdown.total();
    conn.execute(
        "UPDATE users SET karma = ?1 WHERE id = ?2",
        params![total, user_id],
    )
    .context("Failed to store an account score")?;
    Ok(total)
}

/// The net score of one post.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn post_score(conn: &rusqlite::Connection, post_id: i64) -> Result<i64> {
    let score: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(value), 0) FROM post_votes WHERE post_id = ?1",
            params![post_id],
            |row| row.get(0),
        )
        .context("Failed to total a post's votes")?;
    Ok(score)
}

/// The score and the viewer's own vote for each of several posts.
///
/// One query for the scores and one for the viewer's rows, so a page of posts
/// costs the same whatever length it is.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn post_vote_views(
    conn: &rusqlite::Connection,
    post_ids: &[i64],
    voter: Option<&str>,
) -> Result<HashMap<i64, PostVoteView>> {
    let mut views: HashMap<i64, PostVoteView> = post_ids
        .iter()
        .map(|id| (*id, PostVoteView::default()))
        .collect();
    if post_ids.is_empty() {
        return Ok(views);
    }

    let placeholders = vec!["?"; post_ids.len()].join(", ");
    let sql = format!("SELECT post_id, COALESCE(SUM(value), 0) FROM post_votes
                       WHERE post_id IN ({placeholders}) GROUP BY post_id");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(post_ids.iter()))?;
    while let Some(row) = rows.next()? {
        let post_id: i64 = row.get(0)?;
        let score: i64 = row.get(1)?;
        views.entry(post_id).or_default().score = score;
    }

    if let Some(voter) = voter.filter(|key| !key.is_empty()) {
        // The viewer's own rows are fetched by voter rather than by post list:
        // one bound parameter instead of one per post, and the result is
        // filtered against the page below.
        let mut stmt =
            conn.prepare("SELECT post_id, value FROM post_votes WHERE voter_key = ?1")?;
        let mut rows = stmt.query(params![voter])?;
        while let Some(row) = rows.next()? {
            let post_id: i64 = row.get(0)?;
            let value: i64 = row.get(1)?;
            if let Some(view) = views.get_mut(&post_id) {
                view.my_vote = value;
            }
        }
    }

    Ok(views)
}

/// The net votes an account's posts received, split by post kind.
///
/// An opening post and a reply are counted apart because the profile shows
/// them apart: a board regular is recognised by their replies, and a poster by
/// their threads.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn karma_breakdown(conn: &rusqlite::Connection, user_id: i64) -> Result<KarmaBreakdown> {
    let (thread_likes, comment_likes): (i64, i64) = conn
        .query_row(
            "SELECT
                 COALESCE(SUM(CASE WHEN p.is_op = 1 THEN v.value ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN p.is_op = 0 THEN v.value ELSE 0 END), 0)
             FROM post_votes v
             JOIN posts p ON p.id = v.post_id
             WHERE p.user_id = ?1",
            params![user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("Failed to total an account's votes")?;
    Ok(KarmaBreakdown {
        thread_likes,
        comment_likes,
    })
}

/// Give every account the starting score the profile is measured from.
///
/// An account created before voting existed sits at zero, which would read as
/// an account nobody has ever agreed with rather than as an account nobody has
/// voted on yet. Only zero is moved, so an account that has already been voted
/// on keeps the score those votes decided.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn seed_karma_base(conn: &rusqlite::Connection) -> Result<usize> {
    conn.execute(
        "UPDATE users SET karma = ?1 WHERE karma = 0",
        params![KARMASEED],
    )
    .context("Failed to seed account scores")
}

#[cfg(test)]
/// The schema is what makes "one vote per person" true, so the tests are about
/// what a second press does rather than about the happy path.
mod tests {
    use super::{
        cast_vote, karma_breakdown, post_score, post_vote_views, seed_karma_base, voter_key,
        KarmaBreakdown,
    };
    use crate::db;
    use crate::db::schema::install_or_migrate_schema;
    use crate::roles::KARMASEED;
    use anyhow::Result;
    use rusqlite::params;

    /// A database with one board, one account, one thread, and three posts.
    fn database() -> Result<rusqlite::Connection> {
        let conn = rusqlite::Connection::open_in_memory()?;
        install_or_migrate_schema(&conn)?;
        conn.execute("INSERT INTO boards (id, short_name, name) VALUES (1, 'g', 'Genel')", [])?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let user_id = db::create_user(&conn, "anon", "Anonim", &hash, None, "")?;
        conn.execute(
            "INSERT INTO threads (id, board_id, subject) VALUES (1, 1, 'Konu')",
            [],
        )?;
        for (post_id, is_op) in [(10_i64, 1_i64), (11, 0), (12, 0)] {
            conn.execute(
                "INSERT INTO posts (id, thread_id, board_id, is_op, user_id, body, body_html, deletion_token)
                 VALUES (?1, 1, 1, ?2, ?3, 'govde', '<p>govde</p>', 'tok')",
                params![post_id, is_op, user_id],
            )?;
        }
        Ok(conn)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// An account and an address can never land on the same voter key, so a
    /// visitor's address can never take an account's vote back.
    fn voter_keys_cannot_collide() {
        assert_eq!(voter_key(Some(7), Some("abc")).as_deref(), Some("u:7"));
        assert_eq!(voter_key(Some(7), None).as_deref(), Some("u:7"));
        assert_eq!(voter_key(None, Some("abc")).as_deref(), Some("i:abc"));
        assert_eq!(voter_key(None, None), None);
        assert_eq!(voter_key(None, Some("")), None);
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// Pressing the same arrow twice takes the vote back, pressing the other
    /// moves it, and no account can ever hold two votes on one post.
    fn a_vote_can_be_moved_and_taken_back() -> Result<()> {
        let conn = database()?;

        assert_eq!(cast_vote(&conn, 10, "u:1", 1)?, 1, "an upvote scores one");
        assert_eq!(
            cast_vote(&conn, 10, "u:1", -1)?,
            -1,
            "pressing the other arrow moves the vote rather than adding one"
        );
        assert_eq!(
            cast_vote(&conn, 10, "u:1", 0)?,
            0,
            "pressing the pressed arrow again takes the vote back"
        );
        assert_eq!(
            post_score(&conn, 10)?,
            0,
            "a removed vote leaves nothing behind on the post"
        );
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM post_votes WHERE post_id = 10",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0, "taking a vote back deletes the row, not a second one");
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// Two people voting the same way add up; the viewer's own vote is reported
    /// back so the pressed arrow can be shown as pressed.
    fn scores_add_up_and_report_the_viewers_own_vote() -> Result<()> {
        let conn = database()?;
        cast_vote(&conn, 10, "u:1", 1)?;
        cast_vote(&conn, 10, "u:2", 1)?;
        cast_vote(&conn, 10, "i:abc", -1)?;
        cast_vote(&conn, 11, "u:2", -1)?;

        let views = post_vote_views(&conn, &[10, 11, 12], Some("u:1"))?;
        assert_eq!(views[&10].score, 1);
        assert!(views[&10].upvoted());
        assert!(!views[&10].downvoted());
        assert_eq!(views[&11].score, -1);
        assert!(
            !views[&11].upvoted() && !views[&11].downvoted(),
            "another person's vote is not the viewer's own"
        );
        assert_eq!(
            views[&12].score, 0,
            "a post nobody voted on still appears, at zero"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// The profile's numbers are the votes the account's own posts received,
    /// with its threads and its replies counted apart.
    fn the_profile_breaks_the_score_into_threads_and_replies() -> Result<()> {
        let conn = database()?;
        cast_vote(&conn, 10, "u:2", 1)?; // an opening post
        cast_vote(&conn, 10, "u:3", 1)?;
        cast_vote(&conn, 10, "u:4", -1)?;
        cast_vote(&conn, 11, "u:2", 1)?; // a reply
        cast_vote(&conn, 12, "u:2", 1)?; // another reply

        let breakdown = karma_breakdown(&conn, 1)?;
        assert_eq!(breakdown.thread_likes, 1, "two up and a down on the thread");
        assert_eq!(breakdown.comment_likes, 2);
        assert_eq!(breakdown.received(), 3);
        assert_eq!(breakdown.base(), KARMASEED);
        assert_eq!(
            breakdown.total(),
            KARMASEED + 3,
            "the profile leads with the base plus what the votes added"
        );
        assert_eq!(
            db::find_user_by_id(&conn, 1)?.map(|u| u.karma),
            Some(KARMASEED + 3),
            "the stored score the badge and trust tier are decided from follows the votes"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// The three-up, two-down example the score is specified by: an account
    /// starts at the base, gains one per upvote and loses one per downvote, and
    /// taking a vote back moves it back down by exactly as much.
    fn the_score_is_the_base_plus_ups_minus_downs() -> Result<()> {
        let conn = database()?;
        for voter in 2..=4 {
            cast_vote(&conn, 10, &format!("u:{voter}"), 1)?;
        }
        for voter in 5..=6 {
            cast_vote(&conn, 10, &format!("u:{voter}"), -1)?;
        }
        assert_eq!(
            db::find_user_by_id(&conn, 1)?.map(|u| u.karma),
            Some(KARMASEED + 1),
            "three ups and two downs leave the account one above its base"
        );

        cast_vote(&conn, 10, "u:2", 0)?;
        assert_eq!(
            db::find_user_by_id(&conn, 1)?.map(|u| u.karma),
            Some(KARMASEED),
            "taking a vote back moves the account back down by exactly what it had gained"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A new account starts on the base, and the one-off seed that moves
    /// accounts made before voting existed onto it leaves a real score alone.
    fn a_new_account_starts_on_the_base_and_the_seed_never_overwrites_a_score() -> Result<()> {
        let conn = database()?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let fresh = db::create_user(&conn, "yeni", "Yeni", &hash, None, "")?;
        let scored = db::create_user(&conn, "eski", "Eski", &hash, None, "")?;
        conn.execute("UPDATE users SET karma = 7 WHERE id = ?1", [scored])?;
        // An account made before voting existed sits at zero.
        conn.execute("UPDATE users SET karma = 0 WHERE id = ?1", [fresh])?;

        seed_karma_base(&conn)?;

        assert_eq!(
            db::find_user_by_id(&conn, fresh)?.map(|u| u.karma),
            Some(KARMASEED),
            "an account that predates voting is moved onto the base"
        );
        assert_eq!(
            db::find_user_by_id(&conn, scored)?.map(|u| u.karma),
            Some(7),
            "a score that has already been decided is not overwritten"
        );

        // A second run is a no-op rather than a second grant.
        seed_karma_base(&conn)?;
        assert_eq!(
            db::find_user_by_id(&conn, fresh)?.map(|u| u.karma),
            Some(KARMASEED)
        );
        Ok(())
    }

    #[test]
    fn a_default_breakdown_reads_as_the_base_alone() {
        let breakdown = KarmaBreakdown::default();
        assert_eq!(breakdown.received(), 0);
        assert_eq!(breakdown.base(), KARMASEED);
        assert_eq!(breakdown.total(), KARMASEED);
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A new account is created on the base, so the profile never shows a total
    /// of zero for an account that simply has not been voted on yet.
    fn a_new_account_is_created_on_the_base() -> Result<()> {
        let conn = rusqlite::Connection::open_in_memory()?;
        install_or_migrate_schema(&conn)?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let id = db::create_user(&conn, "anon", "Anonim", &hash, None, "")?;
        assert_eq!(db::find_user_by_id(&conn, id)?.map(|u| u.karma), Some(KARMASEED));
        assert_eq!(
            karma_breakdown(&conn, id)?.total(),
            KARMASEED,
            "an account nobody has voted on reads as the base alone"
        );
        Ok(())
    }
}
