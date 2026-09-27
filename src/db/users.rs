//! Anonymous board-account persistence: registration, lookup, and sessions.
//!
//! These tables are separate from `admin_users` on purpose. An administrator
//! is an operator identity, created from the command line and protected by
//! the administration panel; a board account is a throwaway posting identity
//! that carries no real name, address, or contact detail.

use anyhow::{Context as _, Result};
use rusqlite::params;
use rusqlite::OptionalExtension as _;

use crate::models::{User, UserSession};

/// Columns selected for every account lookup, in a fixed order.
const USER_COLUMNS: &str = "id, username, display_name, password_hash, avatar_file, created_at";

fn map_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        password_hash: row.get(3)?,
        avatar_file: row.get(4)?,
        created_at: row.get(5)?,
    })
}

/// Insert a new account and return its row id.
///
/// # Errors
/// Returns an error if the insert fails, which includes the unique-constraint
/// violation raised when the username is already taken.
pub fn create_user(
    conn: &rusqlite::Connection,
    username: &str,
    display_name: &str,
    password_hash: &str,
    avatar_file: Option<&str>,
) -> Result<i64> {
    let id: i64 = conn
        .query_row(
            "INSERT INTO users (username, display_name, password_hash, avatar_file)
             VALUES (?1, ?2, ?3, ?4) RETURNING id",
            params![username, display_name, password_hash, avatar_file],
            |row| row.get(0),
        )
        .context("Failed to create user account")?;
    Ok(id)
}

/// Return whether a username is already registered.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn username_exists(conn: &rusqlite::Connection, username: &str) -> Result<bool> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM users WHERE username = ?1)",
            params![username],
            |row| row.get(0),
        )
        .context("Failed to check username availability")?;
    Ok(exists)
}

/// Look up an account by its unique username.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn find_user_by_username(
    conn: &rusqlite::Connection,
    username: &str,
) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1");
    let mut stmt = conn.prepare_cached(&sql)?;
    Ok(stmt
        .query_row(params![username], map_user)
        .optional()
        .context("Failed to look up user account")?)
}

/// Look up an account by its row id.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn find_user_by_id(conn: &rusqlite::Connection, user_id: i64) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1");
    let mut stmt = conn.prepare_cached(&sql)?;
    Ok(stmt
        .query_row(params![user_id], map_user)
        .optional()
        .context("Failed to look up user account")?)
}

/// Count the registered accounts.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn count_users(conn: &rusqlite::Connection) -> Result<i64> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .context("Failed to count user accounts")?;
    Ok(count)
}

/// Attach a stored avatar file name to an account.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn set_user_avatar(
    conn: &rusqlite::Connection,
    user_id: i64,
    avatar_file: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE users SET avatar_file = ?1 WHERE id = ?2",
        params![avatar_file, user_id],
    )
    .context("Failed to store user avatar")?;
    Ok(())
}

/// Create a session row for an account.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn create_user_session(
    conn: &rusqlite::Connection,
    session_id: &str,
    user_id: i64,
    expires_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO user_sessions (id, user_id, expires_at) VALUES (?1, ?2, ?3)",
        params![session_id, user_id, expires_at],
    )
    .context("Failed to create user session")?;
    Ok(())
}

/// Return a live session, or `None` when it is unknown or expired.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn get_user_session(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<Option<UserSession>> {
    let now = chrono::Utc::now().timestamp();
    let mut stmt = conn.prepare_cached(
        "SELECT id, user_id, created_at, expires_at FROM user_sessions
         WHERE id = ?1 AND expires_at > ?2",
    )?;
    Ok(stmt
        .query_row(params![session_id, now], |row| {
            Ok(UserSession {
                id: row.get(0)?,
                user_id: row.get(1)?,
                created_at: row.get(2)?,
                expires_at: row.get(3)?,
            })
        })
        .optional()
        .context("Failed to load user session")?)
}

/// Delete a single session, used when signing out.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn delete_user_session(conn: &rusqlite::Connection, session_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM user_sessions WHERE id = ?1",
        params![session_id],
    )
    .context("Failed to delete user session")?;
    Ok(())
}

/// Delete a session only when it belongs to the expected account.
///
/// Binding the owner keeps one account from ending another account's session
/// when a stale or forged cookie is presented.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn delete_user_session_for_owner(
    conn: &rusqlite::Connection,
    session_id: &str,
    user_id: i64,
) -> Result<()> {
    conn.execute(
        "DELETE FROM user_sessions WHERE id = ?1 AND user_id = ?2",
        params![session_id, user_id],
    )
    .context("Failed to delete user session")?;
    Ok(())
}

/// Remove every session that has already expired.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn purge_expired_user_sessions(conn: &rusqlite::Connection) -> Result<usize> {
    let now = chrono::Utc::now().timestamp();
    let removed = conn
        .execute(
            "DELETE FROM user_sessions WHERE expires_at <= ?1",
            params![now],
        )
        .context("Failed to purge expired user sessions")?;
    Ok(removed)
}
