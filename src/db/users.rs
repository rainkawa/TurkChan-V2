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

#[cfg(test)]
/// Schema-upgrade coverage for the anonymous-account tables.
mod tests {
    use super::{
        create_user, create_user_session, find_user_by_username, find_user_by_id,
        username_exists,
    };
    use crate::db::schema::{install_or_migrate_schema, normalize_database_schema_version};
    use anyhow::{Context as _, Result};
    use rusqlite::params;

    /// Return whether a schema object of the given kind exists.
    fn object_exists(conn: &rusqlite::Connection, kind: &str, name: &str) -> Result<bool> {
        Ok(conn.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM sqlite_master
                WHERE type = ?1 AND name = ?2
            )",
            params![kind, name],
            |row| row.get(0),
        )?)
    }

    /// Build a database that predates anonymous accounts but holds real data.
    fn pre_account_database() -> Result<rusqlite::Connection> {
        let conn = rusqlite::Connection::open_in_memory()?;
        install_or_migrate_schema(&conn)?;
        // The install above stamps the release baseline, so removing the
        // account objects leaves exactly the drift an older database has.
        conn.execute_batch(
            "DROP INDEX idx_user_sessions_expires;
             DROP INDEX idx_user_sessions_user;
             DROP TABLE user_sessions;
             DROP TABLE users;",
        )?;
        let credential_hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        conn.execute(
            "INSERT INTO admin_users (id, username, password_hash) VALUES (1, 'admin', ?1)",
            [&credential_hash],
        )?;
        conn.execute(
            "INSERT INTO boards (id, short_name, name) VALUES (1, 'g', 'Genel')",
            [],
        )?;
        let thread_id: i64 = conn.query_row(
            "INSERT INTO threads (board_id, subject) VALUES (1, 'Merhaba') RETURNING id",
            [],
            |row| row.get(0),
        )?;
        conn.execute(
            "INSERT INTO posts (thread_id, board_id, body, body_html, deletion_token)
             VALUES (?1, 1, 'ilk gonderi', '<p>ilk gonderi</p>', 'test-token')",
            [thread_id],
        )?;
        Ok(conn)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A database created before anonymous accounts gains the tables and
    /// indexes on startup, and keeps every board, administrator, and post.
    fn older_database_gains_account_tables_without_losing_data() -> Result<()> {
        let conn = pre_account_database()?;

        normalize_database_schema_version(&conn)?;

        for table in ["users", "user_sessions"] {
            assert!(
                object_exists(&conn, "table", table)?,
                "additive table {table} should be installed on an older database"
            );
        }
        for index in ["idx_user_sessions_expires", "idx_user_sessions_user"] {
            assert!(
                object_exists(&conn, "index", index)?,
                "additive account index {index} should be installed"
            );
        }
        assert_eq!(
            conn.query_row("SELECT name FROM boards WHERE id = 1", [], |row| {
                row.get::<_, String>(0)
            })?,
            "Genel",
            "account migration must preserve boards"
        );
        assert_eq!(
            conn.query_row(
                "SELECT username FROM admin_users WHERE id = 1",
                [],
                |row| row.get::<_, String>(0)
            )?,
            "admin",
            "account migration must preserve administrators"
        );
        assert_eq!(
            conn.query_row(
                "SELECT body FROM posts WHERE thread_id = 1",
                [],
                |row| row.get::<_, String>(0)
            )?,
            "ilk gonderi",
            "account migration must preserve posts"
        );
        assert_eq!(
            conn.query_row("SELECT subject FROM threads WHERE id = 1", [], |row| {
                row.get::<_, String>(0)
            })?,
            "Merhaba",
            "account migration must preserve threads"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// The installed tables are usable, not merely present.
    fn installed_account_tables_accept_a_registration_and_session() -> Result<()> {
        let conn = pre_account_database()?;
        normalize_database_schema_version(&conn)?;

        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        assert!(!username_exists(&conn, "anon")?, "username should be free");
        let user_id = create_user(&conn, "anon", "Anonim", &hash, None)?;
        assert!(username_exists(&conn, "anon")?, "username should be taken");

        let found = find_user_by_username(&conn, "anon")?
            .context("registered account should be found by username")?;
        assert_eq!(found.display_name, "Anonim");
        assert_eq!(found.id, user_id);
        let by_id = find_user_by_id(&conn, user_id)?
            .context("registered account should be found by row id")?;
        assert_eq!(by_id.username, "anon");

        let expires_at = chrono::Utc::now().timestamp() + 3600;
        create_user_session(&conn, "sid", user_id, expires_at)?;
        let session = super::get_user_session(&conn, "sid")?
            .context("a live session should resolve")?;
        assert_eq!(session.user_id, user_id);
        assert_eq!(
            super::purge_expired_user_sessions(&conn)?,
            0,
            "a live session must survive the sweep"
        );
        Ok(())
    }
}
