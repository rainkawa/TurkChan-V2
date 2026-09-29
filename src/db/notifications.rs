//! The notification engine: what an account is told, and what it has read.
//!
//! A notification is a record that something happened to somebody. It is kept
//! as a row rather than derived from the posts, the votes, and the messages
//! that caused it, because each of those can be deleted afterwards: a post
//! pruned, a vote taken back, a message removed. A notification that is worked
//! out from its cause stops being true the moment the cause is gone, and the
//! reader is left with a link to nothing.
//!
//! Nothing here is push. A notification is written by the action that caused
//! it, and the live connection that tells a browser about it reads these rows
//! rather than keeping its own copy, so a reader who was offline when it
//! happened sees exactly the same thing as one who was watching.

use anyhow::{Context as _, Result};
use rusqlite::{params, OptionalExtension as _};

/// What happened, in the terms the reader is shown it as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationKind {
    /// Somebody replied to a thread the reader posted in.
    Reply,
    /// A post named the reader.
    Mention,
    /// A vote was cast for one of the reader's posts.
    Upvote,
    /// A vote was cast against one of the reader's posts.
    Downvote,
    /// Somebody wrote to the reader directly.
    DirectMessage,
    /// A moderator acted on something the reader owns.
    Moderation,
    /// The site itself has something to say.
    System,
}

impl NotificationKind {
    /// The stored form of a kind, which is also the only form accepted back.
    ///
    /// Stored as a short lowercase token rather than as the enum's own name so
    /// that a row written today still reads correctly if the type is renamed.
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Reply => "reply",
            Self::Mention => "mention",
            Self::Upvote => "upvote",
            Self::Downvote => "downvote",
            Self::DirectMessage => "direct_message",
            Self::Moderation => "moderation",
            Self::System => "system",
        }
    }

    /// Read a stored kind back, or `None` for one this build does not know.
    ///
    /// A row written by a newer build reads as nothing rather than as an
    /// error, so an older build that meets one does not fail the whole list.
    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "reply" => Some(Self::Reply),
            "mention" => Some(Self::Mention),
            "upvote" => Some(Self::Upvote),
            "downvote" => Some(Self::Downvote),
            "direct_message" => Some(Self::DirectMessage),
            "moderation" => Some(Self::Moderation),
            "system" => Some(Self::System),
            _ => None,
        }
    }

    /// Whether a vote kind counts towards the score shown on a profile.
    ///
    /// Only the two vote kinds do, which is what keeps the number on a profile
    /// equal to the sum of the votes behind it.
    #[must_use]
    pub const fn is_vote(self) -> bool {
        matches!(self, Self::Upvote | Self::Downvote)
    }
}

/// One notification as the reader's list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Row identifier.
    pub id: i64,
    /// What happened.
    pub kind: NotificationKind,
    /// The account that caused it, or `None` once that account is gone.
    pub actor_username: Option<String>,
    /// One line describing it, written by the action that recorded it.
    pub summary: String,
    /// The post it happened on, when it happened on one.
    pub post_id: Option<i64>,
    /// The thread it happened in, for the link back.
    pub thread_id: Option<i64>,
    /// The board it happened in, for the link back.
    pub board_id: Option<i64>,
    /// The board's short name, which is what a link is built from.
    pub board_short: Option<String>,
    /// The message it came from, so a direct-message notification opens the
    /// line rather than a post that does not exist.
    pub message_id: Option<i64>,
    /// When it happened.
    pub created_at: i64,
    /// Whether the reader has seen it.
    pub is_read: bool,
}

/// Everything a new notification needs.
#[derive(Debug, Clone)]
pub struct NewNotification {
    /// The account being told.
    pub user_id: i64,
    /// What happened.
    pub kind: NotificationKind,
    /// The account that caused it, if there is one.
    pub actor_id: Option<i64>,
    /// The post it happened on.
    pub post_id: Option<i64>,
    /// The thread it happened in.
    pub thread_id: Option<i64>,
    /// The board it happened in.
    pub board_id: Option<i64>,
    /// The message it came from, for a direct message.
    pub message_id: Option<i64>,
    /// One line describing it.
    pub summary: String,
}

/// Record one notification, unless it would be telling somebody about
/// themselves.
///
/// A reader told about their own action learns nothing they did not already
/// know, and a wall of it is how a notification list gets ignored entirely, so
/// the row is simply not written.
///
/// # Errors
/// Returns an error if the row cannot be written.
pub fn record_notification(conn: &rusqlite::Connection, notification: &NewNotification) -> Result<()> {
    if notification.actor_id == Some(notification.user_id) {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO notifications
           (user_id, kind, actor_id, post_id, thread_id, board_id, message_id, summary)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            notification.user_id,
            notification.kind.as_db_str(),
            notification.actor_id,
            notification.post_id,
            notification.thread_id,
            notification.board_id,
            notification.message_id,
            notification.summary,
        ],
    )
    .context("Failed to record the notification")?;
    Ok(())
}

/// Return the reader's notifications, newest first.
///
/// A row whose kind this build does not know is left out of the list rather
/// than shown as something unrecognised: a skipped line is better than a line
/// that lies about what happened.
///
/// # Errors
/// Returns an error if the list cannot be read.
pub fn list_notifications(
    conn: &rusqlite::Connection,
    user_id: i64,
    limit: i64,
    offset: i64,
) -> Result<Vec<Notification>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT n.id, n.kind, u.username, n.summary, n.post_id, n.thread_id,
                    n.board_id, b.short_name, n.created_at, n.read_at
             FROM notifications AS n
             LEFT JOIN users AS u ON u.id = n.actor_id
             LEFT JOIN boards AS b ON b.id = n.board_id
             WHERE n.user_id = ?1
             ORDER BY n.id DESC
             LIMIT ?2 OFFSET ?3",
        )
        .context("Failed to prepare the notification list")?;
    let rows = stmt
        .query_map(params![user_id, limit, offset], |row| {
            let kind: String = row.get(1).ok()?;
            let read_at: Option<i64> = row.get(10).ok()?;
            // An unknown kind maps to no row at all rather than to a stand-in,
            // so a newer build's notification cannot be shown as an older one.
            let kind = NotificationKind::from_db_str(&kind)?;
            Ok(Some(Notification {
                id: row.get(0).ok()?,
                kind,
                actor_username: row.get(2).ok()?,
                summary: row.get(3).ok()?,
                post_id: row.get(4).ok()?,
                thread_id: row.get(5).ok()?,
                board_id: row.get(6).ok()?,
                board_short: row.get(7).ok()?,
                message_id: row.get(8).ok()?,
                created_at: row.get(9).ok()?,
                is_read: read_at.is_some(),
            }))
        })
        .context("Failed to read the notification list")?;
    // A row whose kind this build has never heard of is left out of the list
    // rather than shown as something unrecognised: a skipped line is better
    // than a line that lies about what happened.
    Ok(rows
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect())
}

/// Return how many notifications the reader has in total.
///
/// The list is paged, and a page that cannot say how many there are is a page
/// with no way to reach the end of one.
///
/// # Errors
/// Returns an error if the count cannot be read.
pub fn count_notifications(conn: &rusqlite::Connection, user_id: i64) -> Result<i64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .context("Failed to count notifications")?;
    Ok(count)
}

/// Return how many notifications the reader has not read.
///
/// # Errors
/// Returns an error if the count cannot be read.
pub fn unread_notification_count(conn: &rusqlite::Connection, user_id: i64) -> Result<i64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications WHERE user_id = ?1 AND read_at IS NULL",
            params![user_id],
            |row| row.get(0),
        )
        .context("Failed to count unread notifications")?;
    Ok(count)
}

/// Mark one notification as read, for its reader only.
///
/// The reader is part of the write rather than trusted from the caller: a
/// notification marked read by the wrong account would take it off somebody
/// else's list without them ever having seen it.
///
/// # Errors
/// Returns an error if the write fails, and reports whether one was marked.
pub fn mark_notification_read(
    conn: &rusqlite::Connection,
    notification_id: i64,
    user_id: i64,
) -> Result<bool> {
    let updated = conn
        .execute(
            "UPDATE notifications SET read_at = unixepoch()
             WHERE id = ?1 AND user_id = ?2 AND read_at IS NULL",
            params![notification_id, user_id],
        )
        .context("Failed to mark the notification read")?;
    Ok(updated > 0)
}

/// Mark every notification as read for one reader.
///
/// # Errors
/// Returns an error if the write fails, and reports how many were marked.
pub fn mark_all_notifications_read(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> Result<i64> {
    let updated = conn
        .execute(
            "UPDATE notifications SET read_at = unixepoch()
             WHERE user_id = ?1 AND read_at IS NULL",
            params![user_id],
        )
        .context("Failed to mark the notifications read")?;
    Ok(i64::try_from(updated).unwrap_or(i64::MAX))
}

/// Return the most recent notifications recorded after a known point.
///
/// The live connection polls this rather than subscribing to anything: a
/// notification written by another process, or by a restart, is picked up on
/// the next poll exactly like one written in this one, so the reader cannot
/// miss one by having been disconnected at the wrong moment.
///
/// # Errors
/// Returns an error if the list cannot be read.
pub fn notifications_since(
    conn: &rusqlite::Connection,
    user_id: i64,
    after_id: i64,
    limit: i64,
) -> Result<Vec<Notification>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT n.id, n.kind, u.username, n.summary, n.post_id, n.thread_id,
                    n.board_id, b.short_name, n.created_at, n.read_at
             FROM notifications AS n
             LEFT JOIN users AS u ON u.id = n.actor_id
             LEFT JOIN boards AS b ON b.id = n.board_id
             WHERE n.user_id = ?1 AND n.id > ?2
             ORDER BY n.id ASC
             LIMIT ?3",
        )
        .context("Failed to prepare the notification poll")?;
    let rows = stmt
        .query_map(params![user_id, after_id, limit], |row| {
            let kind: String = row.get(1).ok()?;
            let read_at: Option<i64> = row.get(10).ok()?;
            // An unknown kind maps to no row at all rather than to a stand-in,
            // so a newer build's notification cannot be shown as an older one.
            let kind = NotificationKind::from_db_str(&kind)?;
            Ok(Some(Notification {
                id: row.get(0).ok()?,
                kind,
                actor_username: row.get(2).ok()?,
                summary: row.get(3).ok()?,
                post_id: row.get(4).ok()?,
                thread_id: row.get(5).ok()?,
                board_id: row.get(6).ok()?,
                board_short: row.get(7).ok()?,
                message_id: row.get(8).ok()?,
                created_at: row.get(9).ok()?,
                is_read: read_at.is_some(),
            }))
        })
        .context("Failed to read the notification poll")?;
    // A row whose kind this build has never heard of is left out of the list
    // rather than shown as something unrecognised: a skipped line is better
    // than a line that lies about what happened.
    Ok(rows
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect())
}

/// Record that a post was replied to, for the thread's opening poster.
///
/// A reply nobody reads is a reply nobody wrote, so the person who opened the
/// thread is told about it. Their own replies do not notify them, and neither
/// does a reply to a post with no account behind it: there is nobody to tell.
///
/// # Errors
/// Returns an error if the notification cannot be written.
pub fn notify_reply(
    conn: &rusqlite::Connection,
    reply_author_id: Option<i64>,
    thread_op_id: i64,
    post_id: i64,
    thread_id: i64,
    board_id: i64,
    summary: String,
) -> Result<()> {
    let Some(op_author_id) = author_of_post(conn, thread_op_id)? else {
        return Ok(());
    };
    if Some(op_author_id) == reply_author_id {
        return Ok(());
    }
    record_notification(
        conn,
        &NewNotification {
            user_id: op_author_id,
            kind: NotificationKind::Reply,
            actor_id: reply_author_id,
            post_id: Some(post_id),
            thread_id: Some(thread_id),
            board_id: Some(board_id),
            message_id: None,
            summary,
        },
    )
}

/// Record that a post was voted on, for the account that wrote it.
///
/// # Errors
/// Returns an error if the notification cannot be written.
pub fn notify_vote(
    conn: &rusqlite::Connection,
    post_id: i64,
    thread_id: i64,
    board_id: i64,
    voter_id: Option<i64>,
    kind: NotificationKind,
    summary: String,
) -> Result<()> {
    debug_assert!(
        kind.is_vote(),
        "a vote notification must carry a vote kind"
    );
    let Some(author_id) = author_of_post(conn, post_id)? else {
        return Ok(());
    };
    record_notification(
        conn,
        &NewNotification {
            user_id: author_id,
            kind,
            actor_id: voter_id,
            post_id: Some(post_id),
            thread_id: Some(thread_id),
            board_id: Some(board_id),
            message_id: None,
            summary,
        },
    )
}

/// Record that a post named an account.
///
/// # Errors
/// Returns an error if the notification cannot be written.
pub fn notify_mention(
    conn: &rusqlite::Connection,
    mentioned_id: i64,
    author_id: Option<i64>,
    post_id: i64,
    thread_id: i64,
    board_id: i64,
    summary: String,
) -> Result<()> {
    record_notification(
        conn,
        &NewNotification {
            user_id: mentioned_id,
            kind: NotificationKind::Mention,
            actor_id: author_id,
            post_id: Some(post_id),
            thread_id: Some(thread_id),
            board_id: Some(board_id),
            message_id: None,
            summary,
        },
    )
}

/// Record that a direct message was received.
///
/// # Errors
/// Returns an error if the notification cannot be written.
pub fn notify_direct_message(
    conn: &rusqlite::Connection,
    recipient_id: i64,
    sender_id: i64,
    message_id: i64,
    summary: String,
) -> Result<()> {
    record_notification(
        conn,
        &NewNotification {
            user_id: recipient_id,
            kind: NotificationKind::DirectMessage,
            actor_id: Some(sender_id),
            post_id: None,
            thread_id: None,
            board_id: None,
            message_id: Some(message_id),
            summary,
        },
    )
}

/// Return the account that wrote a post, if any.
fn author_of_post(conn: &rusqlite::Connection, post_id: i64) -> Result<Option<i64>> {
    let author: Option<Option<i64>> = conn
        .query_row(
            "SELECT user_id FROM posts WHERE id = ?1",
            params![post_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to read the post author")?;
    Ok(author.flatten())
}

#[cfg(test)]
mod tests {
    use super::{
        list_notifications, mark_all_notifications_read, mark_notification_read,
        notifications_since, notify_direct_message, notify_mention, notify_reply, notify_vote,
        record_notification, unread_notification_count, NewNotification, NotificationKind,
    };
    use crate::db::schema::install_or_migrate_schema;
    use anyhow::Result;

    const READER: i64 = 1;
    const ACTOR: i64 = 2;

    fn test_conn() -> Result<rusqlite::Connection> {
        let conn = rusqlite::Connection::open_in_memory()?;
        // The pool turns this on for every real connection, so a row that only
        // survives without it would be a row production refuses to write.
        conn.execute_batch("PRAGMA foreign_keys = ON")?;
        install_or_migrate_schema(&conn)?;
        for (id, name) in [(READER, "reader"), (ACTOR, "actor")] {
            conn.execute(
                "INSERT INTO users (id, username, display_name, password_hash)
                 VALUES (?1, ?2, ?3, 'not-a-real-hash')",
                rusqlite::params![id, name, name],
            )?;
        }
        Ok(conn)
    }

    fn one(kind: NotificationKind, summary: &str) -> NewNotification {
        NewNotification {
            user_id: READER,
            kind,
            actor_id: Some(ACTOR),
            post_id: Some(1),
            thread_id: Some(1),
            board_id: Some(1),
            message_id: None,
            summary: summary.to_owned(),
        }
    }

    #[test]
    /// A stored kind survives the round trip, and a kind this build has never
    /// heard of reads back as nothing rather than as an error.
    fn every_kind_round_trips() {
        let kinds = [
            NotificationKind::Reply,
            NotificationKind::Mention,
            NotificationKind::Upvote,
            NotificationKind::Downvote,
            NotificationKind::DirectMessage,
            NotificationKind::Moderation,
            NotificationKind::System,
        ];
        for kind in kinds {
            assert_eq!(
                NotificationKind::from_db_str(kind.as_db_str()),
                Some(kind),
                "a kind must survive being stored and read back"
            );
        }
        assert_eq!(NotificationKind::from_db_str("carrier_pigeon"), None);
    }

    #[test]
    /// Nobody is told about their own actions. A wall of "you did what you
    /// just did" is how a notification list gets ignored.
    fn an_account_is_not_told_about_its_own_actions() -> Result<()> {
        let conn = test_conn()?;
        record_notification(
            &conn,
            &NewNotification {
                actor_id: Some(READER),
                ..one(NotificationKind::Reply, "kendi gönderimi")
            },
        )?;
        assert_eq!(unread_notification_count(&conn, READER)?, 0);
        Ok(())
    }

    #[test]
    /// Unread is a count that moves when something happens and stops when the
    /// reader looks, and marking one read must not touch the others.
    fn reading_one_notification_leaves_the_rest_unread() -> Result<()> {
        let conn = test_conn()?;
        record_notification(&conn, &one(NotificationKind::Reply, "birinci"))?;
        record_notification(&conn, &one(NotificationKind::Mention, "ikinci"))?;
        assert_eq!(unread_notification_count(&conn, READER)?, 2);

        let list = list_notifications(&conn, READER, 10, 0)?;
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].summary, "ikinci", "the newest is listed first");
        assert!(mark_notification_read(&conn, list[0].id, READER)?);
        assert_eq!(unread_notification_count(&conn, READER)?, 1);
        assert!(
            !mark_notification_read(&conn, list[0].id, READER)?,
            "reading the same notification twice must not count twice"
        );
        Ok(())
    }

    #[test]
    /// A reader can only mark their own notifications read. Somebody else's
    /// notification marked read would leave it off their list unseen.
    fn a_notification_is_read_only_by_its_reader() -> Result<()> {
        let conn = test_conn()?;
        record_notification(&conn, &one(NotificationKind::Reply, "merhaba"))?;
        let listed = list_notifications(&conn, READER, 10, 0)?;
        assert!(!mark_notification_read(&conn, listed[0].id, ACTOR)?);
        assert_eq!(unread_notification_count(&conn, READER)?, 1);
        Ok(())
    }

    #[test]
    /// "Mark everything read" clears the count in one action, because a reader
    /// who has read their list should not have to press it once per row.
    fn marking_everything_read_clears_the_whole_list() -> Result<()> {
        let conn = test_conn()?;
        for index in 0..5 {
            record_notification(&conn, &one(NotificationKind::Reply, &format!("mesaj {index}")))?;
        }
        assert_eq!(unread_notification_count(&conn, READER)?, 5);
        assert_eq!(mark_all_notifications_read(&conn, READER)?, 5);
        assert_eq!(unread_notification_count(&conn, READER)?, 0);
        assert_eq!(mark_all_notifications_read(&conn, READER)?, 0);
        Ok(())
    }

    #[test]
    /// The live connection reads what is already stored, so a reader who was
    /// not connected when it happened sees the same thing as one who was.
    fn a_poll_returns_only_what_was_recorded_after_it_started() -> Result<()> {
        let conn = test_conn()?;
        record_notification(&conn, &one(NotificationKind::Reply, "eskiden"))?;
        let seen_so_far = list_notifications(&conn, READER, 10, 0)?[0].id;
        assert!(
            notifications_since(&conn, READER, seen_so_far, 10)?.is_empty(),
            "a notification already seen is not repeated on the next poll"
        );
        record_notification(&conn, &one(NotificationKind::Mention, "sonradan"))?;
        let fresh = notifications_since(&conn, READER, seen_so_far, 10)?;
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].summary, "sonradan");
        Ok(())
    }

    #[test]
    /// A reply notifies the account that opened the thread, and a reader's own
    /// reply is not news to them.
    fn a_reply_notifies_the_thread_opener() -> Result<()> {
        let conn = test_conn()?;
        let board_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO threads (id, board_id, subject) VALUES (1, ?1, 'konu')",
            rusqlite::params![board_id],
        )?;
        conn.execute(
            "INSERT INTO posts (id, thread_id, board_id, body, body_html, deletion_token, is_op, user_id)
             VALUES (1, 1, ?1, 'op', 'op', 'token', 1, ?2)",
            rusqlite::params![board_id, READER],
        )?;

        notify_reply(&conn, Some(ACTOR), 1, 2, 1, board_id, "yanıt".to_owned())?;
        assert_eq!(unread_notification_count(&conn, READER)?, 1);

        notify_reply(&conn, Some(READER), 1, 3, 1, board_id, "kendi yanıtım".to_owned())?;
        assert_eq!(
            unread_notification_count(&conn, READER)?,
            1,
            "a reader replying to themselves is not news"
        );
        Ok(())
    }

    #[test]
    /// A vote is told to whoever wrote the post, and the two directions are
    /// kept apart so the number on a profile can be worked out from them.
    fn a_vote_notifies_the_post_author_with_its_direction() -> Result<()> {
        let conn = test_conn()?;
        let board_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO threads (id, board_id, subject) VALUES (1, ?1, 'konu')",
            rusqlite::params![board_id],
        )?;
        conn.execute(
            "INSERT INTO posts (id, thread_id, board_id, body, body_html, deletion_token, is_op, user_id)
             VALUES (1, 1, ?1, 'yazı', 'yazı', 'token', 1, ?2)",
            rusqlite::params![board_id, READER],
        )?;

        notify_vote(
            &conn,
            1,
            1,
            board_id,
            Some(ACTOR),
            NotificationKind::Upvote,
            "oy".to_owned(),
        )?;
        notify_vote(
            &conn,
            1,
            1,
            board_id,
            Some(ACTOR),
            NotificationKind::Downvote,
            "eksi oy".to_owned(),
        )?;
        let listed = list_notifications(&conn, READER, 10, 0)?;
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].kind, NotificationKind::Downvote);
        assert!(NotificationKind::Upvote.is_vote());
        assert!(!NotificationKind::Reply.is_vote());
        Ok(())
    }

    #[test]
    /// A mention reaches the account named, whichever post it was on.
    fn a_mention_reaches_the_account_named() -> Result<()> {
        let conn = test_conn()?;
        notify_mention(&conn, READER, Some(ACTOR), 1, 1, 1, "sen bahsedildin".to_owned())?;
        assert_eq!(unread_notification_count(&conn, READER)?, 1);
        assert_eq!(unread_notification_count(&conn, ACTOR)?, 0);
        Ok(())
    }

    #[test]
    /// A direct message notification carries the message, so clicking it can
    /// open the line rather than a post that does not exist.
    fn a_direct_message_notification_carries_its_message() -> Result<()> {
        let conn = test_conn()?;
        let conversation = crate::db::messages::open_conversation(&conn, ACTOR, READER)
            .map_err(|_| anyhow::anyhow!("open should succeed"))?;
        let message = crate::db::messages::send_message(&conn, conversation, ACTOR, "selam")
            .map_err(|_| anyhow::anyhow!("send should succeed"))?;
        notify_direct_message(&conn, READER, ACTOR, message, "yeni mesaj".to_owned())?;
        let listed = list_notifications(&conn, READER, 10, 0)?;
        assert_eq!(listed[0].kind, NotificationKind::DirectMessage);
        assert_eq!(
            listed[0].message_id,
            Some(message),
            "the notification must point at the message it is about"
        );
        Ok(())
    }
}
