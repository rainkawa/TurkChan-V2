//! Direct messages between accounts.
//!
//! A direct message is a private line between two accounts, so everything
//! about who may send one is decided here rather than in a handler: a blocked
//! pair can neither open a conversation nor continue one, and a conversation
//! is a two-person row that both accounts can resolve to.
//!
//! Deleting a message removes the row for everybody rather than hiding it from
//! one reader. A message that only the recipient could not see would still be a
//! message that exists, and a reader comparing counts would be able to tell.

use anyhow::{Context as _, Result};
use rusqlite::{params, OptionalExtension as _};

/// Longest message body accepted, in characters.
pub const DIRECT_MESSAGE_MAX_CHARS: usize = 4_000;

/// Why a direct message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectMessageRefusal {
    /// The recipient does not exist.
    NoSuchAccount,
    /// One of the two accounts blocked the other.
    Blocked,
    /// The body was empty or longer than [`DIRECT_MESSAGE_MAX_CHARS`].
    Body,
}

/// Why a write did not happen.
///
/// A refusal the reader can act on and a database that could not be reached
/// are different answers, and a caller that cannot tell them apart would show
/// somebody "this account has blocked you" when the truth is that the write
/// never left the process. Keeping them in one type is what lets the writes
/// below use `?` for the storage half and still refuse for the other one.
#[derive(Debug)]
pub enum DirectMessageError {
    /// The write was refused, and this is why.
    Refused(DirectMessageRefusal),
    /// The write could not be attempted or completed.
    Storage(anyhow::Error),
}

impl DirectMessageError {
    /// Return the refusal this names, if it names one.
    #[must_use]
    pub fn refusal(&self) -> Option<DirectMessageRefusal> {
        match self {
            Self::Refused(refusal) => Some(*refusal),
            Self::Storage(_) => None,
        }
    }
}

impl From<DirectMessageRefusal> for DirectMessageError {
    fn from(refusal: DirectMessageRefusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<anyhow::Error> for DirectMessageError {
    fn from(error: anyhow::Error) -> Self {
        Self::Storage(error)
    }
}

impl std::fmt::Display for DirectMessageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(refusal) => write!(formatter, "direct message refused: {refusal:?}"),
            Self::Storage(error) => write!(formatter, "direct message storage failure: {error}"),
        }
    }
}

impl std::error::Error for DirectMessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(_) => None,
            Self::Storage(error) => Some(error.as_ref()),
        }
    }
}

/// One message as the reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectMessage {
    /// Row identifier, used to address the message for deletion.
    pub id: i64,
    /// The account that wrote it.
    pub sender_id: i64,
    /// The account that wrote it, by login name.
    pub sender_username: String,
    /// Message text.
    pub body: String,
    /// When it was sent.
    pub created_at: i64,
}

/// One row in the conversation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSummary {
    /// The conversation's row identifier.
    pub id: i64,
    /// The other account's login name.
    pub other_username: String,
    /// The other account's display name.
    pub other_display_name: String,
    /// Text of the most recent message, for the list preview.
    pub last_body: String,
    /// When the most recent message was sent.
    pub last_at: i64,
    /// Messages the reader has not read, which is zero or more.
    pub unread: i64,
    /// Whether the other account blocked the reader, which hides the thread
    /// rather than reporting a refusal the reader could do nothing about.
    pub blocked_by_other: bool,
}

/// Return whether `blocker_id` has blocked `blocked_id`.
///
/// # Errors
/// Returns an error if the lookup fails.
pub fn is_blocked(
    conn: &rusqlite::Connection,
    blocker_id: i64,
    blocked_id: i64,
) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM user_blocks WHERE blocker_id = ?1 AND blocked_id = ?2",
            params![blocker_id, blocked_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to read the block list")?;
    Ok(found.is_some())
}

/// Return whether either account has blocked the other.
///
/// A block is a wall in both directions: the person who blocked somebody does
/// not expect to keep receiving them either, so a conversation cannot be
/// opened from the far side while a block stands.
fn either_way_blocked(
    conn: &rusqlite::Connection,
    first: i64,
    second: i64,
) -> Result<bool> {
    Ok(is_blocked(conn, first, second)? || is_blocked(conn, second, first)?)
}

/// Block `blocked_id`, or unblock them when the block already stands.
///
/// # Errors
/// Returns an error if the accounts are the same or the write fails.
pub fn set_block(
    conn: &rusqlite::Connection,
    blocker_id: i64,
    blocked_id: i64,
    blocked: bool,
) -> Result<()> {
    if blocker_id == blocked_id {
        anyhow::bail!("Bir hesabı kendisinden engelleyemezsin.");
    }
    if blocked {
        conn.execute(
            "INSERT INTO user_blocks (blocker_id, blocked_id) VALUES (?1, ?2)
             ON CONFLICT (blocker_id, blocked_id) DO NOTHING",
            params![blocker_id, blocked_id],
        )
        .context("Failed to block the account")?;
    } else {
        conn.execute(
            "DELETE FROM user_blocks WHERE blocker_id = ?1 AND blocked_id = ?2",
            params![blocker_id, blocked_id],
        )
        .context("Failed to unblock the account")?;
    }
    Ok(())
}

/// Return the accounts `user_id` has blocked.
///
/// # Errors
/// Returns an error if the list cannot be read.
pub fn list_blocked(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> Result<Vec<(i64, String)>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT b.blocked_id, u.username
             FROM user_blocks AS b
             JOIN users AS u ON u.id = b.blocked_id
             WHERE b.blocker_id = ?1
             ORDER BY u.username ASC",
        )
        .context("Failed to prepare the block list")?;
    let rows = stmt
        .query_map(params![user_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .context("Failed to read the block list")?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Find the conversation between two accounts, if one exists.
///
/// A conversation is a pair, so it is found by its two members rather than
/// looked up by whoever opened it: this returns the same conversation from
/// either side, which is what makes a message the only thing needed to keep
/// writing.
///
/// # Errors
/// Returns an error if the lookup fails.
fn find_conversation(
    conn: &rusqlite::Connection,
    first: i64,
    second: i64,
) -> Result<Option<i64>> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT a.conversation_id
             FROM conversation_members AS a
             JOIN conversation_members AS b
               ON b.conversation_id = a.conversation_id
             WHERE a.user_id = ?1 AND b.user_id = ?2
             LIMIT 1",
            params![first, second],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to find the conversation")?;
    Ok(found)
}

/// Return the conversation between two accounts, or `None` when they have
/// never written to each other.
///
/// # Errors
/// Returns an error if the lookup fails.
pub fn conversation_between(
    conn: &rusqlite::Connection,
    first: i64,
    second: i64,
) -> Result<Option<i64>> {
    find_conversation(conn, first, second)
}

/// Open, or reuse, the conversation between two accounts.
///
/// The two members are written in the order their ids sort into, so both
/// accounts running this at the same time land on the same conversation rather
/// than each opening one of their own.
///
/// # Errors
/// Returns [`DirectMessageRefusal::NoSuchAccount`] when the recipient does not
/// exist and [`DirectMessageRefusal::Blocked`] when either account has blocked
/// the other.
pub fn open_conversation(
    conn: &rusqlite::Connection,
    sender_id: i64,
    recipient_id: i64,
) -> Result<i64, DirectMessageError> {
    if sender_id == recipient_id {
        return Err(DirectMessageRefusal::NoSuchAccount.into());
    }
    let recipient_exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM users WHERE id = ?1",
            params![recipient_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to look up the recipient account")
        .map_err(|_| DirectMessageRefusal::NoSuchAccount)?;
    if recipient_exists.is_none() {
        return Err(DirectMessageRefusal::NoSuchAccount.into());
    }
    if either_way_blocked(conn, sender_id, recipient_id)
        .context("Failed to read the block list")
        .map_err(|_| DirectMessageRefusal::Blocked)?
    {
        return Err(DirectMessageRefusal::Blocked.into());
    }
    if let Some(existing) =
        find_conversation(conn, sender_id, recipient_id).context("Failed to find the conversation")?
    {
        return Ok(existing);
    }

    let (first, second) = if sender_id < recipient_id {
        (sender_id, recipient_id)
    } else {
        (recipient_id, sender_id)
    };
    let inserted = conn
        .execute(
            "INSERT OR IGNORE INTO conversations (created_at, updated_at)
             VALUES (unixepoch(), unixepoch())",
            [],
        )
        .context("Failed to open the conversation")?;
    let conversation_id = if inserted == 0 {
        find_conversation(conn, first, second)
            .context("Failed to find the conversation")?
            .ok_or(DirectMessageError::from(DirectMessageRefusal::Blocked))?
    } else {
        conn.last_insert_rowid()
    };
    for member in [first, second] {
        conn.execute(
            "INSERT OR IGNORE INTO conversation_members (conversation_id, user_id, last_read_at)
             VALUES (?1, ?2, 0)",
            params![conversation_id, member],
        )
        .context("Failed to add the conversation member")?;
    }
    Ok(conversation_id)
}

/// Return a message body ready to store, or why it cannot be.
///
/// Trimming first means a body of nothing but spaces is an empty body rather
/// than a message that renders as one blank line.
fn checked_body(body: &str) -> Result<String, DirectMessageError> {
    let trimmed = body.trim();
    if trimmed.is_empty() || trimmed.chars().count() > DIRECT_MESSAGE_MAX_CHARS {
        return Err(DirectMessageRefusal::Body.into());
    }
    Ok(trimmed.to_owned())
}

/// Send one message inside a conversation.
///
/// The sender is not taken on trust: the message row is written only when the
/// sender is a member, so a caller that guessed a conversation id writes
/// nothing rather than posting into somebody else's line.
///
/// # Errors
/// Returns an error if the body is unusable, the sender is not a member, or
/// the write fails.
pub fn send_message(
    conn: &rusqlite::Connection,
    conversation_id: i64,
    sender_id: i64,
    body: &str,
) -> Result<i64, DirectMessageError> {
    let body = checked_body(body)?;
    let is_member: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM conversation_members
             WHERE conversation_id = ?1 AND user_id = ?2",
            params![conversation_id, sender_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to read the conversation members")
        .map_err(|_| DirectMessageRefusal::Blocked)?;
    if is_member.is_none() {
        return Err(DirectMessageRefusal::Blocked.into());
    }
    conn.execute(
        "INSERT INTO direct_messages (conversation_id, sender_id, body)
         VALUES (?1, ?2, ?3)",
        params![conversation_id, sender_id, body],
    )
    .context("Failed to store the message")
    .map_err(|_| DirectMessageRefusal::Body)?;
    conn.execute(
        "UPDATE conversations SET updated_at = unixepoch() WHERE id = ?1",
        params![conversation_id],
    )
    .context("Failed to stamp the conversation")?;
    // The sender has by definition read their own message, so the cursor moves
    // past it. A sender who then saw their own message as unread would have to
    // open the thread to clear a number they caused.
    conn.execute(
        "UPDATE conversation_members
         SET last_read_at = unixepoch()
         WHERE conversation_id = ?1 AND user_id = ?2",
        params![conversation_id, sender_id],
    )
    .context("Failed to advance the sender's read cursor")?;
    Ok(conn.last_insert_rowid())
}

/// Return the messages in one conversation, oldest first.
///
/// A reader only ever sees a conversation they are a member of, so the member
/// check is part of the read rather than something the caller is trusted to
/// have done.
///
/// # Errors
/// Returns an error if the reader is not a member or the read fails.
pub fn conversation_messages(
    conn: &rusqlite::Connection,
    conversation_id: i64,
    reader_id: i64,
    limit: i64,
) -> Result<Vec<DirectMessage>> {
    let is_member: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM conversation_members
             WHERE conversation_id = ?1 AND user_id = ?2",
            params![conversation_id, reader_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to read the conversation members")?;
    if is_member.is_none() {
        anyhow::bail!("Bu sohbete erişimin yok.");
    }
    let mut stmt = conn
        .prepare_cached(
            "SELECT m.id, m.sender_id, u.username, m.body, m.created_at
             FROM direct_messages AS m
             JOIN users AS u ON u.id = m.sender_id
             WHERE m.conversation_id = ?1
             ORDER BY m.id ASC
             LIMIT ?2",
        )
        .context("Failed to prepare the message read")?;
    let rows = stmt
        .query_map(params![conversation_id, limit], |row| {
            Ok(DirectMessage {
                id: row.get(0)?,
                sender_id: row.get(1)?,
                sender_username: row.get(2)?,
                body: row.get(3)?,
                created_at: row.get(4)?,
            })
        })
        .context("Failed to read the messages")?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Mark every message in a conversation as read for one member.
///
/// # Errors
/// Returns an error if the reader is not a member or the write fails.
pub fn mark_conversation_read(
    conn: &rusqlite::Connection,
    conversation_id: i64,
    reader_id: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE conversation_members SET last_read_at = unixepoch()
         WHERE conversation_id = ?1 AND user_id = ?2",
        params![conversation_id, reader_id],
    )
    .context("Failed to advance the read cursor")?;
    Ok(())
}

/// Return the total unread message count across every conversation.
///
/// # Errors
/// Returns an error if the count cannot be read.
pub fn unread_message_count(conn: &rusqlite::Connection, user_id: i64) -> Result<i64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*)
             FROM direct_messages AS m
             JOIN conversation_members AS member
               ON member.conversation_id = m.conversation_id
              AND member.user_id = ?1
             WHERE m.created_at > member.last_read_at AND m.sender_id <> ?1",
            params![user_id],
            |row| row.get(0),
        )
        .context("Failed to count unread messages")?;
    Ok(count)
}

/// Return every conversation the account takes part in, newest first.
///
/// A conversation the other account has blocked is still listed, because
/// blocking somebody stops new messages; it does not rewrite a history the
/// reader already has. The flag is returned so the reader can be told the
/// line is closed without the existing messages disappearing under them.
///
/// # Errors
/// Returns an error if the list cannot be read.
pub fn list_conversations(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> Result<Vec<ConversationSummary>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT c.id, u.username, u.display_name,
                    COALESCE((SELECT body FROM direct_messages AS last
                              WHERE last.conversation_id = c.id
                              ORDER BY last.id DESC LIMIT 1), ''),
                    COALESCE((SELECT created_at FROM direct_messages AS last
                              WHERE last.conversation_id = c.id
                              ORDER BY last.id DESC LIMIT 1), c.created_at),
                    (SELECT COUNT(*) FROM direct_messages AS unread
                     WHERE unread.conversation_id = c.id
                       AND unread.created_at > member.last_read_at
                       AND unread.sender_id <> member.user_id),
                    EXISTS (SELECT 1 FROM user_blocks AS b
                            WHERE b.blocker_id = other.user_id
                              AND b.blocked_id = member.user_id)
             FROM conversation_members AS member
             JOIN conversations AS c ON c.id = member.conversation_id
             JOIN conversation_members AS other
               ON other.conversation_id = c.id AND other.user_id <> member.user_id
             JOIN users AS u ON u.id = other.user_id
             WHERE member.user_id = ?1
             ORDER BY last_at DESC, c.id DESC",
        )
        .context("Failed to prepare the conversation list")?;
    let rows = stmt
        .query_map(params![user_id], |row| {
            Ok(ConversationSummary {
                id: row.get(0)?,
                other_username: row.get(1)?,
                other_display_name: row.get(2)?,
                last_body: row.get(3)?,
                last_at: row.get(4)?,
                unread: row.get(5)?,
                blocked_by_other: row.get::<_, i64>(6)? != 0,
            })
        })
        .context("Failed to read the conversation list")?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Delete one message, for its sender only.
///
/// A message is the sender's to take back. Deleting somebody else's would let
/// a reader erase a record of what was said to them, so the sender is checked
/// against the row and a message that is not theirs is left exactly as it was.
///
/// # Errors
/// Returns an error if the message is not the caller's, and reports whether
/// one was removed.
pub fn delete_message(
    conn: &rusqlite::Connection,
    message_id: i64,
    sender_id: i64,
) -> Result<bool> {
    let removed = conn
        .execute(
            "DELETE FROM direct_messages WHERE id = ?1 AND sender_id = ?2",
            params![message_id, sender_id],
        )
        .context("Failed to delete the message")?;
    Ok(removed > 0)
}

/// Delete a whole conversation for one member, and for both when both leave.
///
/// A member who leaves keeps their copy of what was said: the row that goes is
/// the membership, not the messages. The conversation itself is removed only
/// once nobody is left in it, so no conversation row is ever kept alive by a
/// member who cannot see it.
///
/// # Errors
/// Returns an error if the reader is not a member or the write fails.
pub fn leave_conversation(
    conn: &rusqlite::Connection,
    conversation_id: i64,
    user_id: i64,
) -> Result<()> {
    let is_member: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM conversation_members
             WHERE conversation_id = ?1 AND user_id = ?2",
            params![conversation_id, user_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to read the conversation members")?;
    if is_member.is_none() {
        anyhow::bail!("Bu sohbete erişimin yok.");
    }
    conn.execute(
        "DELETE FROM conversation_members WHERE conversation_id = ?1 AND user_id = ?2",
        params![conversation_id, user_id],
    )
    .context("Failed to leave the conversation")?;
    conn.execute(
        "DELETE FROM conversations
         WHERE id = ?1
           AND NOT EXISTS (
               SELECT 1 FROM conversation_members WHERE conversation_id = ?1
           )",
        params![conversation_id],
    )
    .context("Failed to close the conversation")?;
    Ok(())
}

/// Return whether an account is a member of a conversation.
///
/// The page read uses this to tell "this line is empty" apart from "this line
/// is not yours": both show no messages, and only one of them is a page.
///
/// # Errors
/// Returns an error if the membership cannot be read.
pub fn conversation_includes_member(
    conn: &rusqlite::Connection,
    conversation_id: i64,
    user_id: i64,
) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM conversation_members
             WHERE conversation_id = ?1 AND user_id = ?2",
            params![conversation_id, user_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to read the conversation members")?;
    Ok(found.is_some())
}

/// Return the account on the other side of a conversation.
///
/// # Errors
/// Returns an error if the lookup fails, and `None` when the conversation has
/// no other member, which a pair-only conversation cannot have.
pub fn other_conversation_member(
    conn: &rusqlite::Connection,
    conversation_id: i64,
    user_id: i64,
) -> Result<Option<i64>> {
    let other: Option<i64> = conn
        .query_row(
            "SELECT user_id FROM conversation_members
             WHERE conversation_id = ?1 AND user_id <> ?2
             LIMIT 1",
            params![conversation_id, user_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to read the conversation members")?;
    Ok(other)
}

#[cfg(test)]
mod tests {
    use super::{
        conversation_between, conversation_messages, delete_message, is_blocked, leave_conversation,
        list_blocked, list_conversations, mark_conversation_read, open_conversation, send_message,
        set_block, unread_message_count, DirectMessageRefusal, DIRECT_MESSAGE_MAX_CHARS,
    };
    use crate::db::schema::install_or_migrate_schema;
    use anyhow::Result;

    const FIRST: i64 = 1;
    const SECOND: i64 = 2;
    const THIRD: i64 = 3;

    /// Return the refusal a write was refused for.
    ///
    /// A refusal and a storage failure are kept apart in the error type, so a
    /// test that only cares about the refusal asks for it rather than
    /// asserting on a whole error it cannot build.
    fn refusal_of(error: super::DirectMessageError) -> DirectMessageRefusal {
        error
            .refusal()
            .expect("an in-memory database must not fail to store")
    }

    fn test_conn() -> Result<rusqlite::Connection> {
        let conn = rusqlite::Connection::open_in_memory()?;
        install_or_migrate_schema(&conn)?;
        for (id, name) in [(FIRST, "first"), (SECOND, "second"), (THIRD, "third")] {
            conn.execute(
                "INSERT INTO users (id, username, display_name, password_hash)
                 VALUES (?1, ?2, ?3, 'not-a-real-hash')",
                rusqlite::params![id, name, name],
            )?;
        }
        Ok(conn)
    }

    #[test]
    /// Two accounts find the same conversation whichever one opens it, so
    /// opening is not a second conversation waiting to be created by accident.
    fn a_conversation_is_the_same_line_from_either_side() -> Result<()> {
        let conn = test_conn()?;
        let opened = open_conversation(&conn, FIRST, SECOND).map_err(|_| anyhow::anyhow!("refused"))?;
        let found = open_conversation(&conn, SECOND, FIRST).map_err(|_| anyhow::anyhow!("refused"))?;
        assert_eq!(opened, found, "the pair must resolve to one conversation");
        assert_eq!(
            conversation_between(&conn, FIRST, SECOND)?,
            Some(opened)
        );
        Ok(())
    }

    #[test]
    /// A block closes the line in both directions. A wall that only held from
    /// one side would still be a way to reach somebody who asked not to be
    /// reached, by signing in as the other person is not the test — reaching
    /// them from the blocked account is.
    fn a_block_stops_messages_in_both_directions() -> Result<()> {
        let conn = test_conn()?;
        assert!(is_blocked(&conn, FIRST, SECOND).is_ok());
        set_block(&conn, FIRST, SECOND, true)?;
        assert!(is_blocked(&conn, FIRST, SECOND)?);
        assert!(
            is_blocked(&conn, SECOND, FIRST)?,
            "the far side must not be able to reach across the block either"
        );
        assert_eq!(
            open_conversation(&conn, SECOND, FIRST).map_err(refusal_of),
            Err(DirectMessageRefusal::Blocked)
        );
        Ok(())
    }

    #[test]
    /// A block also closes a line that already existed, because a block that
    /// only stopped new conversations would let anybody keep writing into an
    /// old one.
    fn a_block_stops_a_conversation_that_already_exists() -> Result<()> {
        let conn = test_conn()?;
        let conversation = open_conversation(&conn, FIRST, SECOND)
            .map_err(|_| anyhow::anyhow!("open should succeed"))?;
        send_message(&conn, conversation, FIRST, "merhaba")
            .map_err(|_| anyhow::anyhow!("send should succeed"))?;
        set_block(&conn, SECOND, FIRST, true)?;
        assert_eq!(
            send_message(&conn, conversation, FIRST, "tekrar").map_err(refusal_of),
            Err(DirectMessageRefusal::Blocked)
        );
        Ok(())
    }

    #[test]
    /// The recipient's own unread count is what moves when a message arrives,
    /// and the sender's does not: a person has read what they wrote.
    fn unread_counts_the_recipient_not_the_sender() -> Result<()> {
        let conn = test_conn()?;
        let conversation = open_conversation(&conn, FIRST, SECOND)
            .map_err(|_| anyhow::anyhow!("open should succeed"))?;
        send_message(&conn, conversation, FIRST, "merhaba")
            .map_err(|_| anyhow::anyhow!("send should succeed"))?;
        assert_eq!(unread_message_count(&conn, SECOND)?, 1);
        assert_eq!(
            unread_message_count(&conn, FIRST)?,
            0,
            "the sender has read their own message"
        );
        mark_conversation_read(&conn, conversation, SECOND)?;
        assert_eq!(unread_message_count(&conn, SECOND)?, 0);
        Ok(())
    }

    #[test]
    /// A reader who is not a member gets nothing, and a sender who is not a
    /// member writes nothing. A guessed conversation id must not be a key.
    fn a_non_member_can_neither_read_nor_write() -> Result<()> {
        let conn = test_conn()?;
        let conversation = open_conversation(&conn, FIRST, SECOND)
            .map_err(|_| anyhow::anyhow!("open should succeed"))?;
        assert!(conversation_messages(&conn, conversation, THIRD, 50).is_err());
        assert_eq!(
            send_message(&conn, conversation, THIRD, "sizmemişim").map_err(refusal_of),
            Err(DirectMessageRefusal::Blocked)
        );
        Ok(())
    }

    #[test]
    /// A message is the sender's to take back and nobody else's. Deleting
    /// somebody else's would let a reader erase a record of what was said to
    /// them.
    fn only_the_sender_can_delete_a_message() -> Result<()> {
        let conn = test_conn()?;
        let conversation = open_conversation(&conn, FIRST, SECOND)
            .map_err(|_| anyhow::anyhow!("open should succeed"))?;
        let message = send_message(&conn, conversation, FIRST, "merhaba")
            .map_err(|_| anyhow::anyhow!("send should succeed"))?;
        assert!(!delete_message(&conn, message, SECOND)?);
        assert_eq!(conversation_messages(&conn, conversation, FIRST, 50)?.len(), 1);
        assert!(delete_message(&conn, message, FIRST)?);
        assert!(conversation_messages(&conn, conversation, FIRST, 50)?.is_empty());
        Ok(())
    }

    #[test]
    /// A body of nothing but spaces is an empty body rather than a message
    /// that renders as one blank line.
    fn an_empty_body_is_refused() -> Result<()> {
        let conn = test_conn()?;
        let conversation = open_conversation(&conn, FIRST, SECOND)
            .map_err(|_| anyhow::anyhow!("open should succeed"))?;
        assert_eq!(
            send_message(&conn, conversation, FIRST, "   \n  ").map_err(refusal_of),
            Err(DirectMessageRefusal::Body)
        );
        let too_long = "x".repeat(DIRECT_MESSAGE_MAX_CHARS + 1);
        assert_eq!(
            send_message(&conn, conversation, FIRST, &too_long).map_err(refusal_of),
            Err(DirectMessageRefusal::Body)
        );
        Ok(())
    }

    #[test]
    /// The list carries what a reader needs to recognise a thread without
    /// opening it: who it is with, what was last said, and how much is unread.
    fn the_conversation_list_carries_the_preview() -> Result<()> {
        let conn = test_conn()?;
        let conversation = open_conversation(&conn, FIRST, SECOND)
            .map_err(|_| anyhow::anyhow!("open should succeed"))?;
        send_message(&conn, conversation, SECOND, "selam")
            .map_err(|_| anyhow::anyhow!("send should succeed"))?;
        let list = list_conversations(&conn, FIRST)?;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].other_username, "second");
        assert_eq!(list[0].last_body, "selam");
        assert_eq!(list[0].unread, 1);
        assert!(!list[0].blocked_by_other);
        Ok(())
    }

    #[test]
    /// Leaving takes the membership, not the words. The other account keeps
    /// what was said to them, and the conversation goes only once nobody is
    /// left holding it.
    fn leaving_keeps_the_other_side_history() -> Result<()> {
        let conn = test_conn()?;
        let conversation = open_conversation(&conn, FIRST, SECOND)
            .map_err(|_| anyhow::anyhow!("open should succeed"))?;
        send_message(&conn, conversation, FIRST, "görüşürüz")
            .map_err(|_| anyhow::anyhow!("send should succeed"))?;
        leave_conversation(&conn, conversation, FIRST)?;
        assert!(list_conversations(&conn, FIRST)?.is_empty());
        assert_eq!(
            list_conversations(&conn, SECOND)?.len(),
            1,
            "the other side keeps their copy of the exchange"
        );
        leave_conversation(&conn, conversation, SECOND)?;
        assert!(
            conversation_between(&conn, FIRST, SECOND)?.is_none(),
            "an empty conversation is not left behind"
        );
        Ok(())
    }

    #[test]
    /// A block list is a list, and a block can be taken back off it.
    fn a_block_can_be_lifted() -> Result<()> {
        let conn = test_conn()?;
        set_block(&conn, FIRST, SECOND, true)?;
        set_block(&conn, FIRST, THIRD, true)?;
        assert_eq!(list_blocked(&conn, FIRST)?.len(), 2);
        set_block(&conn, FIRST, SECOND, false)?;
        assert_eq!(list_blocked(&conn, FIRST)?.len(), 1);
        Ok(())
    }

    #[test]
    /// An account cannot block itself, which would be a row with no other end.
    fn an_account_cannot_block_itself() -> Result<()> {
        let conn = test_conn()?;
        assert!(set_block(&conn, FIRST, FIRST, true).is_err());
        Ok(())
    }

    #[test]
    /// Messages to somebody who is not there are refused rather than silently
    /// written to a conversation nobody will ever read.
    fn a_missing_recipient_is_refused() -> Result<()> {
        let conn = test_conn()?;
        assert_eq!(
            open_conversation(&conn, FIRST, 9999).map_err(refusal_of),
            Err(DirectMessageRefusal::NoSuchAccount)
        );
        Ok(())
    }
}
