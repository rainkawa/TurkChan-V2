//! Post votes, and the account score they add up to.
//!
//! One row per post per voter is the whole model: the primary key is
//! `(post_id, user_id)`, so "one vote per person" is a property of the
//! schema rather than something a handler has to remember to check. Casting a
//! vote is therefore an upsert, pressing the same arrow twice deletes the row,
//! and pressing the other one overwrites it — which is exactly the behaviour an
//! imageboard reader expects, and none of it needs a read-modify-write.
//!
//! The voter is a foreign key, so a vote belongs to an account and can always
//! be taken back by the account that cast it. Both references cascade: a
//! deleted account takes its votes with it, and so does a deleted post.
//!
//! The score is never stored on a post. It is the sum of that post's rows, so a
//! deleted post takes its votes with it and a score cannot drift away from the
//! votes that produced it.
//!
//! Voting belongs to accounts alone. A visitor without one is not counted, and
//! a vote therefore always has a name behind it and always has an author who
//! can be shown what their post was worth. An account's score is the sum of the
//! votes its own posts received, with no starting number added: a single upvote
//! is worth exactly one point, and a profile that cannot show a single upvote
//! is not showing the score at all.

use anyhow::{Context as _, Result};
use rusqlite::params;
use std::collections::HashMap;

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

    /// The number the profile leads with.
    #[must_use]
    pub const fn total(&self) -> i64 {
        self.received()
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
    voter_id: i64,
    value: i64,
) -> Result<i64> {
    let value = value.clamp(-1, 1);
    if value == 0 {
        conn.execute(
            "DELETE FROM post_votes WHERE post_id = ?1 AND user_id = ?2",
            params![post_id, voter_id],
        )
        .context("Failed to remove a post vote")?;
    } else {
        conn.execute(
            "INSERT INTO post_votes (post_id, user_id, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (post_id, user_id) DO UPDATE SET value = excluded.value",
            params![post_id, voter_id, value],
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

/// The vote one account already holds on a post, or zero when it holds none.
///
/// A press arrives as a direction, not as an intent, so this is what tells
/// apart the first press of an arrow from the second: the same direction twice
/// means the reader is taking the vote back, and only the stored row can say
/// which of the two this one is.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn current_vote(conn: &rusqlite::Connection, post_id: i64, user_id: i64) -> Result<i64> {
    match conn.query_row(
        "SELECT value FROM post_votes WHERE post_id = ?1 AND user_id = ?2",
        params![post_id, user_id],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(value) => Ok(value),
        // Holding no vote is the ordinary answer, not a failure to look.
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(error) => Err(error).context("Failed to read a post's standing vote"),
    }
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
    viewer_id: Option<i64>,
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

    if let Some(viewer_id) = viewer_id {
        // The viewer's own rows are fetched by viewer rather than by post
        // list: one bound parameter instead of one per post, and the result is
        // filtered against the page below. A visitor without an account gets
        // scores but no pressed arrow, because there is no vote of theirs to
        // report.
        let mut stmt = conn.prepare("SELECT post_id, value FROM post_votes WHERE user_id = ?1")?;
        let mut rows = stmt.query(params![viewer_id])?;
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
#[cfg(test)]
/// The schema is what makes "one vote per person" true, so the tests are about
/// what a second press does rather than about the happy path.
mod tests {
    use super::{
        cast_vote, current_vote, karma_breakdown, post_score, post_vote_views,
        KarmaBreakdown,
    };
    use crate::db;
    use crate::db::schema::install_or_migrate_schema;
    use anyhow::Result;
    use rusqlite::params;

    /// A database with one board, one account that writes, and three others who
    /// can vote, over one thread with an opening post and two replies.
    fn database() -> Result<(rusqlite::Connection, i64)> {
        let conn = rusqlite::Connection::open_in_memory()?;
        // Both references cascade, and a cascade is what one of these tests is
        // about, so the connection has to enforce them the way the pool does.
        conn.execute_batch("PRAGMA foreign_keys = ON")?;
        install_or_migrate_schema(&conn)?;
        conn.execute("INSERT INTO boards (id, short_name, name) VALUES (1, 'g', 'Genel')", [])?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let author = db::create_user(&conn, "yazar", "Yazar", &hash, None, "")?;
        // Rows 2 through 5: the readers who vote on the posts below.
        for username in ["okuyucu", "bir", "iki", "ucuncu"] {
            db::create_user(&conn, username, username, &hash, None, "")?;
        }
        conn.execute(
            "INSERT INTO threads (id, board_id, subject) VALUES (1, 1, 'Konu')",
            [],
        )?;
        for (post_id, is_op) in [(10_i64, 1_i64), (11, 0), (12, 0)] {
            conn.execute(
                "INSERT INTO posts (id, thread_id, board_id, is_op, user_id, body, body_html, deletion_token)
                 VALUES (?1, 1, 1, ?2, ?3, 'govde', '<p>govde</p>', 'tok')",
                params![post_id, is_op, author],
            )?;
        }
        Ok((conn, author))
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// Pressing the same arrow twice takes the vote back, pressing the other
    /// moves it, and no account can ever hold two votes on one post.
    fn a_vote_can_be_moved_and_taken_back() -> Result<()> {
        let (conn, _) = database()?;

        assert_eq!(cast_vote(&conn, 10, 2, 1)?, 1, "an upvote scores one");
        assert_eq!(
            cast_vote(&conn, 10, 2, -1)?,
            -1,
            "pressing the other arrow moves the vote rather than adding one"
        );
        assert_eq!(
            cast_vote(&conn, 10, 2, 0)?,
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
    /// back so the pressed arrow can be shown as pressed, and a visitor with no
    /// account still sees the score even though no arrow of theirs is pressed.
    fn scores_add_up_and_report_the_viewers_own_vote() -> Result<()> {
        let (conn, _) = database()?;
        cast_vote(&conn, 10, 2, 1)?;
        cast_vote(&conn, 10, 3, 1)?;
        cast_vote(&conn, 10, 4, -1)?;
        cast_vote(&conn, 11, 3, -1)?;

        let views = post_vote_views(&conn, &[10, 11, 12], Some(2))?;
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

        let anonymous = post_vote_views(&conn, &[10, 11, 12], None)?;
        assert_eq!(anonymous[&10].score, 1, "a score is public to every reader");
        assert_eq!(
            anonymous[&10].my_vote, 0,
            "a reader with no account has pressed nothing"
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
        let (conn, author) = database()?;
        cast_vote(&conn, 10, 2, 1)?; // an opening post
        cast_vote(&conn, 10, 3, 1)?;
        cast_vote(&conn, 10, 4, -1)?;
        cast_vote(&conn, 11, 2, 1)?; // a reply
        cast_vote(&conn, 12, 2, 1)?; // another reply

        let breakdown = karma_breakdown(&conn, author)?;
        assert_eq!(breakdown.thread_likes, 1, "two up and a down on the thread");
        assert_eq!(breakdown.comment_likes, 2);
        assert_eq!(breakdown.received(), 3);
        assert_eq!(
            breakdown.total(),
            3,
            "there is no starting number: three votes is a score of three"
        );
        assert_eq!(
            db::find_user_by_id(&conn, author)?.map(|u| u.karma),
            Some(3),
            "the stored score the badge and trust tier are decided from follows the votes"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A single upvote is worth exactly one point and shows as one. There is no
    /// base to hide it behind, so an account that has been agreed with once
    /// reads as one point rather than as a number that was already there.
    fn one_upvote_is_visible_on_the_profile() -> Result<()> {
        let (conn, author) = database()?;
        cast_vote(&conn, 10, 2, 1)?;

        assert_eq!(karma_breakdown(&conn, author)?.total(), 1);
        assert_eq!(db::find_user_by_id(&conn, author)?.map(|u| u.karma), Some(1));

        cast_vote(&conn, 10, 2, 0)?;
        assert_eq!(
            karma_breakdown(&conn, author)?.total(),
            0,
            "taking the only vote back takes the score back to nothing"
        );
        assert_eq!(db::find_user_by_id(&conn, author)?.map(|u| u.karma), Some(0));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// Two ups and a down is one above zero, and taking a vote back moves the
    /// account down by exactly what it had gained rather than leaving a residue
    /// behind.
    fn the_score_is_ups_minus_downs_and_never_drifts() -> Result<()> {
        let (conn, author) = database()?;
        for voter in 2..=3 {
            cast_vote(&conn, 10, voter, 1)?;
        }
        cast_vote(&conn, 10, 4, -1)?;
        assert_eq!(
            db::find_user_by_id(&conn, author)?.map(|u| u.karma),
            Some(1),
            "two ups and a down leave the account one above zero"
        );

        cast_vote(&conn, 10, 2, 0)?;
        assert_eq!(
            db::find_user_by_id(&conn, author)?.map(|u| u.karma),
            Some(0),
            "taking a vote back moves the account back by exactly what it had gained"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A vote cannot outlive the account that cast it, and cannot outlive the
    /// post it was cast on, so neither a deleted account nor a deleted post
    /// leaves a number behind that nothing on the site can explain.
    fn a_vote_goes_away_with_its_account_or_its_post() -> Result<()> {
        let (conn, author) = database()?;
        cast_vote(&conn, 10, 2, 1)?;
        cast_vote(&conn, 11, 3, 1)?;
        assert_eq!(karma_breakdown(&conn, author)?.total(), 2);

        conn.execute("DELETE FROM posts WHERE id = 11", [])?;
        assert_eq!(
            karma_breakdown(&conn, author)?.total(),
            1,
            "a deleted post takes its votes with it"
        );

        conn.execute("DELETE FROM users WHERE id = 2", [])?;
        assert_eq!(
            karma_breakdown(&conn, author)?.total(),
            0,
            "a deleted account takes its votes with it"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A press arrives as a direction, and only the stored row can say whether
    /// this is the first press of that arrow or the second one taking it back.
    fn the_standing_vote_is_what_tells_a_first_press_from_a_second() -> Result<()> {
        let (conn, _) = database()?;

        assert_eq!(
            current_vote(&conn, 10, 2)?,
            0,
            "an account that has not voted has no standing vote"
        );
        cast_vote(&conn, 10, 2, 1)?;
        assert_eq!(current_vote(&conn, 10, 2)?, 1);
        cast_vote(&conn, 10, 2, -1)?;
        assert_eq!(
            current_vote(&conn, 10, 2)?,
            -1,
            "moving a vote replaces it rather than adding a second one"
        );
        cast_vote(&conn, 10, 2, 0)?;
        assert_eq!(current_vote(&conn, 10, 2)?, 0, "a taken-back vote leaves nothing");
        assert_eq!(
            current_vote(&conn, 11, 2)?,
            0,
            "one account's vote on one post says nothing about another post"
        );
        Ok(())
    }

    #[test]
    fn a_default_breakdown_reads_as_nothing_received() {
        let breakdown = KarmaBreakdown::default();
        assert_eq!(breakdown.received(), 0);
        assert_eq!(breakdown.total(), 0);
    }
}
