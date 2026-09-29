//! Anonymous board-account persistence: registration, lookup, sessions, and
//! the public profile queries that back the profile page.
//!
//! These tables are separate from `admin_users` on purpose. An administrator
//! is an operator identity, created from the command line and protected by
//! the administration panel; a board account is a throwaway posting identity
//! that carries no real name, address, or contact detail.
//!
//! A post carries the id of the account that wrote it in the nullable
//! `posts.user_id` column. Posts written before accounts existed, and posts
//! written without signing in, keep a `NULL` there and simply never appear on
//! a profile page.

use anyhow::{Context as _, Result};
use rusqlite::params;
use rusqlite::OptionalExtension as _;
use std::collections::HashMap;

use crate::models::{ProfilePost, ProfilePostScope, ProfileStats, ProfileThread, User, UserSession};
use crate::roles::{AccountStatus, UserRole};

/// Columns selected for every account lookup, in a fixed order.
const USER_COLUMNS: &str = "id, username, display_name, password_hash, avatar_file, bio, karma, \
                            role, status, suspended_until, created_at";

fn map_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let role: String = row.get(7)?;
    let status: String = row.get(8)?;
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        password_hash: row.get(3)?,
        avatar_file: row.get(4)?,
        bio: row.get(5)?,
        karma: row.get(6)?,
        // Both columns are read through their own parser rather than
        // deserialized, so a row this build does not understand resolves to the
        // least authority instead of failing the whole lookup.
        role: UserRole::from_stored(&role),
        status: AccountStatus::from_stored(&status),
        suspended_until: row.get(9)?,
        created_at: row.get(10)?,
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
    bio: &str,
) -> Result<i64> {
    let id: i64 = conn
        .query_row(
            "INSERT INTO users (username, display_name, password_hash, avatar_file, bio)
             VALUES (?1, ?2, ?3, ?4, ?5) RETURNING id",
            params![username, display_name, password_hash, avatar_file, bio],
            |row| row.get(0),
        )
        .context("Failed to create user account")?;
    Ok(id)
}

/// Description shown on an administrator's generated profile.
const ADMIN_PROFILE_BIO: &str = "Site yöneticisi.";

/// Give an administrator the public profile the account menu links to.
///
/// The header account menu offers every signed-in identity a "Profili Gör"
/// entry, and an administrator's board name is their `admin_users` name. That
/// link is a dead end without a matching `users` row, so an administrator is
/// given a profile of their own.
///
/// The generated row identifies the operator on the board but cannot be signed
/// into: its password hash covers 32 random bytes that are discarded right
/// after hashing, so the stored hash is a real, well-formed Argon2id hash that
/// matches no password a visitor could present. An administrator whose name is
/// already registered keeps that account, and no existing row is ever
/// overwritten.
///
/// Safe to call repeatedly: it is a no-op once the profile exists.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn ensure_admin_profile(conn: &rusqlite::Connection, admin_name: &str) -> Result<()> {
    // Board usernames are stored trimmed and lower-cased, and the profile route
    // matches a requested name the same way, so the row is written that way.
    let username = admin_name.trim().to_lowercase();
    if username.is_empty() || username_exists(conn, &username)? {
        return Ok(());
    }
    let unusable_hash = admin_profile_password_hash()?;
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, avatar_file, bio)
         VALUES (?1, ?2, ?3, NULL, ?4)",
        params![username, admin_name.trim(), unusable_hash, ADMIN_PROFILE_BIO],
    )
    .context("Failed to create the administrator's profile")?;
    tracing::info!(target: "db", %username, "Created the administrator's board profile");
    Ok(())
}

/// Hash a value that is generated and immediately discarded.
///
/// The result is a valid Argon2id hash that no password can match, used to give
/// an administrator's board profile a credential column that cannot be signed
/// into.
///
/// # Errors
/// Returns an error if hashing fails.
fn admin_profile_password_hash() -> Result<String> {
    let secret = uuid::Uuid::new_v4().simple().to_string();
    crate::utils::crypto::hash_password(&secret)
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

/// Map each of the given posts to the login name of the account that wrote it.
///
/// Only a post linked to an account appears in the result. A post written
/// before accounts existed, one posted without signing in, and one whose poster
/// asked to keep it off their profile all carry no `user_id`, and a share is
/// named after the account behind the post rather than after the name typed
/// into the form: a name is free text, so reading it as an identity would let
/// anyone publish a share in somebody else's name.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn post_share_authors(
    conn: &rusqlite::Connection,
    post_ids: &[i64],
) -> Result<HashMap<i64, String>> {
    if post_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = post_ids
        .iter()
        .enumerate()
        .map(|(index, _)| format!("?{}", index + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT p.id, u.username
         FROM posts p
         JOIN users u ON u.id = p.user_id
         WHERE p.id IN ({placeholders})"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(post_ids.iter().copied()), |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut authors = HashMap::with_capacity(post_ids.len());
    for row in rows {
        let (post_id, username) = row?;
        authors.insert(post_id, username);
    }
    Ok(authors)
}

/// The account a post belongs to, as a thread page needs to show it.
///
/// Posts carry the name that was typed into the form, which is free text, so
/// the account behind a post is read from the join rather than from the post.
/// The avatar is optional because an account may not have chosen one, and the
/// role is carried because a moderator's post should read differently from an
/// ordinary one without the reader having to know who wrote it.
#[derive(Debug, Clone)]
pub struct PostAuthorProfile {
    /// Login name, used for the profile link.
    pub username: String,
    /// Name shown next to the avatar.
    pub display_name: String,
    /// Account role, rendered as a badge.
    pub role: crate::roles::UserRole,
    /// Stored avatar file, when the account has chosen one.
    pub avatar_file: Option<String>,
}

/// Load the account behind each of the given posts.
///
/// One query for the whole page: a post carries a nullable `user_id`, so the
/// join drops the ones written before accounts existed, which is correct
/// because there is no account to describe.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn post_author_profiles(
    conn: &rusqlite::Connection,
    post_ids: &[i64],
) -> Result<HashMap<i64, PostAuthorProfile>> {
    if post_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = post_ids
        .iter()
        .enumerate()
        .map(|(index, _)| format!("?{}", index + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT p.id, u.username, u.display_name, u.role, u.avatar_file
         FROM posts p
         JOIN users u ON u.id = p.user_id
         WHERE p.id IN ({placeholders})"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(post_ids.iter().copied()), |row| {
        let role: String = row.get(3)?;
        Ok((
            row.get::<_, i64>(0)?,
            PostAuthorProfile {
                username: row.get(1)?,
                display_name: row.get(2)?,
                role: crate::roles::UserRole::from_stored(&role),
                avatar_file: row.get(4)?,
            },
        ))
    })?;
    let mut profiles = HashMap::with_capacity(post_ids.len());
    for row in rows {
        let (post_id, profile) = row?;
        profiles.insert(post_id, profile);
    }
    Ok(profiles)
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

/// Set the staff role of an account.
///
/// The role is the only stored grant of administration access, so this one
/// column decides who may open the panel. Everything else an operator can do
/// to an account is a separate, narrower write.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn set_user_role(
    conn: &rusqlite::Connection,
    user_id: i64,
    role: UserRole,
) -> Result<()> {
    conn.execute(
        "UPDATE users SET role = ?1 WHERE id = ?2",
        params![role.as_str(), user_id],
    )
    .context("Failed to set user role")?;
    Ok(())
}

/// Set the moderation state of an account.
///
/// A ban is stored as the state itself so it survives any later change of role
/// or karma, and a suspension carries the second it ends so it lifts without
/// anyone having to clear it.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn set_user_status(
    conn: &rusqlite::Connection,
    user_id: i64,
    status: AccountStatus,
    suspended_until: Option<i64>,
) -> Result<()> {
    conn.execute(
        "UPDATE users SET status = ?1, suspended_until = ?2 WHERE id = ?3",
        params![status.as_str(), suspended_until, user_id],
    )
    .context("Failed to set user status")?;
    Ok(())
}

/// List accounts for the administration panel, newest identifiers last.
///
/// Only the columns the panel shows are read back: the password hash is not
/// among them, so a rendered page cannot leak one even by accident.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn list_users(
    conn: &rusqlite::Connection,
    limit: i64,
    offset: i64,
) -> Result<Vec<User>> {
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM users ORDER BY id LIMIT ?1 OFFSET ?2"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt
        .query_map(params![limit, offset], map_user)
        .context("Failed to list user accounts")?;
    let mut users = Vec::new();
    for row in rows {
        users.push(row?);
    }
    Ok(users)
}

/// Count the accounts a filtered listing would show.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn count_users_matching(
    conn: &rusqlite::Connection,
    search: Option<&str>,
) -> Result<i64> {
    let count = match search {
        Some(term) => {
            let like = format!("%{term}%");
            conn.query_row(
                "SELECT COUNT(*) FROM users WHERE username LIKE ?1 OR display_name LIKE ?1",
                params![like],
                |row| row.get(0),
            )
        }
        None => conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0)),
    };
    count.context("Failed to count matching user accounts")
}

/// List the accounts a search term matches, newest identifiers last.
///
/// The two characters `LIKE` treats as wildcards are escaped, so a reader who
/// types a percent sign is looking for a percent sign. Left unescaped, typing
/// one would return every account on the site to a reader who only meant one
/// character, which is both wrong and slow.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn search_users(conn: &rusqlite::Connection, search: &str, limit: i64) -> Result<Vec<User>> {
    let term: String = search.trim().chars().take(crate::db::search::SEARCH_MAX_CHARS).collect();
    let like = format!(
        "%{}%",
        term.replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM users
         WHERE username LIKE ?1 ESCAPE '\\' OR display_name LIKE ?1 ESCAPE '\\'
         ORDER BY id LIMIT ?2"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt
        .query_map(params![like, limit], map_user)
        .context("Failed to search user accounts")?;
    let mut users = Vec::new();
    for row in rows {
        users.push(row?);
    }
    Ok(users)
}

/// Count the accounts holding a staff role, used to refuse removing the last one.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn count_users_with_role(conn: &rusqlite::Connection, role: UserRole) -> Result<i64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM users WHERE role = ?1",
            params![role.as_str()],
            |row| row.get(0),
        )
        .context("Failed to count accounts holding a role")?;
    Ok(count)
}

/// Give the site owner role to the board profile of the first administrator.
///
/// Ownership belongs to whoever set the site up, and the first row in
/// `admin_users` is that person. The grant is written onto the board profile
/// the administrator already has, so it is visible on the site and survives a
/// restart, and it is a no-op once any account already holds ownership.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn ensure_owner_profile(conn: &rusqlite::Connection) -> Result<()> {
    if count_users_with_role(conn, UserRole::Owner)? > 0 {
        return Ok(());
    }
    let first_admin: Option<String> = conn
        .query_row(
            "SELECT username FROM admin_users ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to read the first administrator")?;
    let Some(admin_name) = first_admin else {
        return Ok(());
    };
    ensure_admin_profile(conn, &admin_name)?;
    let username = admin_name.trim().to_lowercase();
    if username.is_empty() {
        return Ok(());
    }
    conn.execute(
        "UPDATE users SET role = ?1 WHERE username = ?2 AND role = 'user'",
        params![UserRole::Owner.as_str(), username],
    )
    .context("Failed to grant the site owner role")?;
    Ok(())
}

/// Rename the name an account is shown under.
///
/// The account menu, every post header, and the profile page all read this
/// column, so changing it is the single edit that renames the account in one
/// place instead of a copy per surface.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn update_display_name(
    conn: &rusqlite::Connection,
    user_id: i64,
    display_name: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE users SET display_name = ?1 WHERE id = ?2",
        params![display_name, user_id],
    )
    .context("Failed to update user display name")?;
    Ok(())
}

/// Move an account to a new unique username.
///
/// The username is part of the account's public address, so a caller that
/// renames an account has to know whether the new name was free: this fails
/// with the same unique-constraint violation `create_user` raises when it is
/// not, and callers treat that as a rejected form rather than a crash.
///
/// # Errors
/// Returns an error if the database operation fails, which includes the
/// unique-constraint violation raised when the username is already taken.
pub fn update_username(
    conn: &rusqlite::Connection,
    user_id: i64,
    username: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE users SET username = ?1 WHERE id = ?2",
        params![username, user_id],
    )
    .context("Failed to update user username")?;
    Ok(())
}

/// Replace the short description an account publishes on its profile.
///
/// The description is optional, so an empty string is a real value here and not
/// a missing one: it is what clears the line on the profile page.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn update_bio(conn: &rusqlite::Connection, user_id: i64, bio: &str) -> Result<()> {
    conn.execute(
        "UPDATE users SET bio = ?1 WHERE id = ?2",
        params![bio, user_id],
    )
    .context("Failed to update user bio")?;
    Ok(())
}

/// Replace the stored Argon2id hash of an account.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn update_password_hash(
    conn: &rusqlite::Connection,
    user_id: i64,
    password_hash: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        params![password_hash, user_id],
    )
    .context("Failed to update user password")?;
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

/// End every session an account holds, used after a password change.
///
/// Changing a password is how an owner takes back an account, so the sessions
/// that were opened with the old secret have to stop working: leaving them
/// alive is what makes a stolen session survive the fix.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn delete_user_sessions_for_user(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> Result<usize> {
    conn.execute(
        "DELETE FROM user_sessions WHERE user_id = ?1",
        params![user_id],
    )
    .context("Failed to delete user sessions")
}

/// Attach a post to the account that wrote it.
///
/// The link is written after the post row exists, so a posting path that never
/// resolves an account simply leaves the column `NULL`. The `idx_posts_user`
/// index keeps the profile listings over those rows cheap.
///
/// # Errors
/// Returns an error if the database operation fails.
pub fn link_post_to_account(
    conn: &rusqlite::Connection,
    post_id: i64,
    user_id: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE posts SET user_id = ?1 WHERE id = ?2",
        params![user_id, post_id],
    )
    .context("Failed to link post to account")?;
    Ok(())
}

/// Return the activity totals shown in a profile header.
///
/// Only posts that still belong to a live thread are counted. A row whose
/// thread is gone is content a visitor can no longer open, and counting it
/// would keep a deleted post visible as a tab badge that the listing below
/// refuses to show.
///
/// The score is read from the votes the account's own posts received, and split
/// by post kind, so the header can show what the threads earned apart from what
/// the replies earned. It is never read from `users.karma`: that column is a
/// cache of the same number, and a header that could disagree with it is worse
/// than no cache at all.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn profile_stats(conn: &rusqlite::Connection, user_id: i64) -> Result<ProfileStats> {
    let (post_count, reply_count): (i64, i64) = conn
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM posts p
                   JOIN threads t ON t.id = p.thread_id WHERE p.user_id = ?1),
                 (SELECT COUNT(*) FROM posts p
                   JOIN threads t ON t.id = p.thread_id
                   WHERE p.user_id = ?1 AND p.is_op = 0)",
            params![user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("Failed to count account posts")?;
    let thread_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM posts p
             JOIN threads t ON t.id = p.thread_id
             WHERE p.user_id = ?1 AND p.is_op = 1",
            params![user_id],
            |row| row.get(0),
        )
        .context("Failed to count account threads")?;
    let breakdown = super::votes::karma_breakdown(conn, user_id)?;
    Ok(ProfileStats {
        thread_count,
        post_count,
        reply_count,
        thread_likes: breakdown.thread_likes,
        comment_likes: breakdown.comment_likes,
        karma: breakdown.total(),
    })
}

/// Columns selected for one row of a profile post listing, in a fixed order.
const PROFILE_POST_COLUMNS: &str = "p.id, p.thread_id, b.short_name, \
     COALESCE(NULLIF(p.subject, ''), NULLIF(t.subject, '')), p.body, p.is_op, p.created_at";

/// Map one profile post row.
fn map_profile_post(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProfilePost> {
    Ok(ProfilePost {
        id: row.get(0)?,
        thread_id: row.get(1)?,
        board_short: row.get(2)?,
        subject: row.get(3)?,
        body: row.get(4)?,
        is_op: row.get::<_, i32>(5)? != 0,
        created_at: row.get(6)?,
    })
}

/// Return one page of an account's posts, newest first.
///
/// The scope picks the history tab the listing serves. The thread join is
/// inner, not left, so a post whose thread no longer exists is never listed:
/// that row is content a visitor cannot open, whether it was left behind by a
/// deletion, an older build, or a restore. The rows are what a profile page
/// renders, so they deliberately carry no password, address, or contact data
/// from any account.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn list_profile_posts(
    conn: &rusqlite::Connection,
    user_id: i64,
    scope: ProfilePostScope,
    limit: i64,
    offset: i64,
) -> Result<Vec<ProfilePost>> {
    let op_filter = match scope {
        ProfilePostScope::All => "",
        ProfilePostScope::Replies => "AND p.is_op = 0",
    };
    let sql = format!(
        "SELECT {PROFILE_POST_COLUMNS}
         FROM posts p
         JOIN boards b ON b.id = p.board_id
         JOIN threads t ON t.id = p.thread_id
         WHERE p.user_id = ?1 {op_filter}
         ORDER BY p.created_at DESC, p.id DESC
         LIMIT ?2 OFFSET ?3"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let posts = stmt
        .query_map(params![user_id, limit, offset], map_profile_post)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(posts)
}

/// Return one page of the threads an account opened, newest first.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn list_profile_threads(
    conn: &rusqlite::Connection,
    user_id: i64,
    limit: i64,
    offset: i64,
) -> Result<Vec<ProfileThread>> {
    let mut stmt = conn.prepare_cached(
        "SELECT t.id, op.id, b.short_name, t.subject, op.body, t.created_at, t.reply_count
         FROM posts op
         JOIN threads t ON t.id = op.thread_id
         JOIN boards b ON b.id = t.board_id
         WHERE op.user_id = ?1 AND op.is_op = 1
         ORDER BY t.created_at DESC, t.id DESC
         LIMIT ?2 OFFSET ?3",
    )?;
    let threads = stmt
        .query_map(params![user_id, limit, offset], |row| {
            Ok(ProfileThread {
                thread_id: row.get(0)?,
                post_id: row.get(1)?,
                board_short: row.get(2)?,
                subject: row.get(3)?,
                body: row.get(4)?,
                created_at: row.get(5)?,
                reply_count: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(threads)
}

/// Return the board short name that owns each of the given posts.
///
/// A `>>N` reference points at a post without naming its board, so an excerpt
/// rendered outside its own thread resolves the reference through this map and
/// links to the board that actually holds the post. Identifiers with no row are
/// simply absent and render as plain text.
///
/// # Errors
/// Returns an error if the database query fails.
pub fn resolve_post_boards(
    conn: &rusqlite::Connection,
    post_ids: &[i64],
) -> Result<HashMap<i64, String>> {
    if post_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = std::iter::repeat_n("?", post_ids.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT p.id, b.short_name
         FROM posts p
         JOIN boards b ON b.id = p.board_id
         WHERE p.id IN ({placeholders})"
    );
    // Prepared outside the cache: the placeholder count changes with the
    // number of references on the page, so caching would only evict hot
    // statements.
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(post_ids.iter().copied()), |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut boards = HashMap::with_capacity(post_ids.len());
    for row in rows {
        let (post_id, board_short) = row.context("Read post board mapping failed")?;
        boards.insert(post_id, board_short);
    }
    Ok(boards)
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
        count_users, create_user, create_user_session, delete_user_sessions_for_user,
        ensure_admin_profile, ensure_owner_profile, find_user_by_id, find_user_by_username,
        get_user_session, list_users, search_users, set_user_avatar, set_user_role,
        set_user_status, update_bio, update_display_name, update_password_hash, update_username,
        username_exists,
    };
    use crate::roles::{AccountStatus, UserRole};
    use crate::models::ProfilePostScope;
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
    /// A database that already knows the account tables but predates the
    /// profile columns gains them in place, and keeps its accounts and posts.
    fn older_database_gains_profile_columns_without_losing_data() -> Result<()> {
        let conn = pre_account_database()?;
        normalize_database_schema_version(&conn)?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let user_id = create_user(&conn, "anon", "Anonim", &hash, None, "eski bio")?;
        // Rewind to the shape a released build leaves behind: the profile
        // columns are gone, and the index that reads them went with them.
        conn.execute_batch(
            "DROP INDEX IF EXISTS idx_posts_user;
             ALTER TABLE posts DROP COLUMN user_id;
             ALTER TABLE users DROP COLUMN karma;
             ALTER TABLE users DROP COLUMN bio;",
        )?;

        normalize_database_schema_version(&conn)?;

        let account = find_user_by_username(&conn, "anon")?
            .context("the existing account should survive the profile migration")?;
        assert_eq!(account.bio, "", "an appended bio column starts empty");
        assert_eq!(
            account.karma, 0,
            "the migration must not rewrite an existing row's score; the startup seed moves it onto the base"
        );
        assert!(conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM posts WHERE id = 1 AND body = 'ilk gonderi')",
            [],
            |row| row.get::<_, bool>(0)
        )?, "the pre-existing post must survive the profile migration");
        assert_eq!(
            super::profile_stats(&conn, user_id)?.post_count,
            0,
            "posts written before accounts existed belong to no profile"
        );

        super::link_post_to_account(&conn, 1, user_id)?;
        let stats = super::profile_stats(&conn, user_id)?;
        assert_eq!(stats.post_count, 1);
        assert_eq!(stats.reply_count, 1);
        assert_eq!(stats.thread_count, 0);
        let posts = super::list_profile_posts(&conn, user_id, ProfilePostScope::All, 10, 0)?;
        assert_eq!(posts.len(), 1);
        assert_eq!(
            posts.first().map(|post| post.board_short.as_str()),
            Some("g"),
            "a profile post names the board it belongs to"
        );
        assert_eq!(
            super::resolve_post_boards(&conn, &[1, 999])?.get(&1).map(String::as_str),
            Some("g")
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
        let user_id = create_user(&conn, "anon", "Anonim", &hash, None, "merhaba")?;
        assert!(username_exists(&conn, "anon")?, "username should be taken");

        let found = find_user_by_username(&conn, "anon")?
            .context("registered account should be found by username")?;
        assert_eq!(found.display_name, "Anonim");
        assert_eq!(found.id, user_id);
        assert_eq!(found.bio, "merhaba");
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

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// An administrator gets a public profile under the same name the account
    /// menu links to, and the row cannot be signed into.
    fn administrator_gets_a_profile_that_cannot_be_signed_into() -> Result<()> {
        let conn = pre_account_database()?;
        normalize_database_schema_version(&conn)?;

        ensure_admin_profile(&conn, "Admin")?;
        let account = find_user_by_username(&conn, "admin")?
            .context("the administrator should have a public profile")?;
        assert_eq!(
            account.display_name, "Admin",
            "the profile keeps the operator's own name"
        );
        assert!(
            !crate::utils::crypto::verify_password("Admin", &account.password_hash)?,
            "a generated profile must never accept a password"
        );

        // Signing in again must not add a second row or disturb the first.
        ensure_admin_profile(&conn, "Admin")?;
        assert_eq!(count_users(&conn)?, 1);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// An administrator who shares a name with a registered account keeps that
    /// account instead of overwriting it.
    fn administrator_profile_never_overwrites_a_registered_account() -> Result<()> {
        let conn = pre_account_database()?;
        normalize_database_schema_version(&conn)?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        create_user(&conn, "admin", "Gerçek Anonim", &hash, None, "gerçek hesap")?;

        ensure_admin_profile(&conn, "admin")?;

        let account = find_user_by_username(&conn, "admin")?
            .context("the registered account should still exist")?;
        assert_eq!(account.display_name, "Gerçek Anonim");
        assert_eq!(account.bio, "gerçek hesap");
        assert_eq!(count_users(&conn)?, 1);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A post whose thread is gone is content nobody can open, so it stays off
    /// the profile listing and out of the tab totals.
    fn posts_left_without_a_thread_stay_off_the_profile() -> Result<()> {
        let conn = pre_account_database()?;
        normalize_database_schema_version(&conn)?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let user_id = create_user(&conn, "anon", "Anonim", &hash, None, "selam")?;
        super::link_post_to_account(&conn, 1, user_id)?;
        assert_eq!(super::profile_stats(&conn, user_id)?.post_count, 1);

        // Remove the thread but keep its post, which is the shape a deletion or
        // a restore can leave behind. The pragma keeps the post from going with
        // its thread, so the listing is actually exercised.
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DELETE FROM threads WHERE id = (SELECT thread_id FROM posts WHERE id = 1);",
        )?;

        let posts = super::list_profile_posts(&conn, user_id, ProfilePostScope::All, 10, 0)?;
        assert!(
            posts.is_empty(),
            "a post with no surviving thread must not be listed"
        );
        assert_eq!(
            super::profile_stats(&conn, user_id)?.post_count,
            0,
            "an unopenable post must not be counted either"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// The account settings screen renames an account and replaces its
    /// credential, and a rename onto a taken name is refused rather than
    /// silently moving the account on top of its neighbour.
    fn account_settings_rename_and_replace_the_credential() -> Result<()> {
        let conn = pre_account_database()?;
        normalize_database_schema_version(&conn)?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let user_id = create_user(&conn, "anon", "Anonim", &hash, None, "selam")?;
        let neighbour = create_user(&conn, "arkadas", "Arkadaş", &hash, None, "başka")?;

        update_display_name(&conn, user_id, "Yeni Ad")?;
        update_username(&conn, user_id, "yeni-ad")?;
        update_bio(&conn, user_id, "yeni tanitim")?;
        let replacement = crate::utils::crypto::hash_password("DegistirilmisParola")?;
        update_password_hash(&conn, user_id, &replacement)?;
        set_user_avatar(&conn, user_id, "5.png")?;

        let renamed = find_user_by_id(&conn, user_id)?
            .context("the renamed account should still resolve by row id")?;
        assert_eq!(renamed.display_name, "Yeni Ad");
        assert_eq!(renamed.username, "yeni-ad");
        assert_eq!(renamed.bio, "yeni tanitim");
        assert_eq!(renamed.avatar_file.as_deref(), Some("5.png"));
        assert!(
            crate::utils::crypto::verify_password("DegistirilmisParola", &renamed.password_hash)?,
            "the account must sign in with the replacement password"
        );
        assert!(
            !crate::utils::crypto::verify_password("Hunter2Hunter2", &renamed.password_hash)?,
            "the old password must stop working"
        );

        // The neighbour is untouched by someone else's rename...
        let other = find_user_by_id(&conn, neighbour)?
            .context("the neighbouring account should still exist")?;
        assert_eq!(other.username, "arkadas");
        assert_eq!(other.display_name, "Arkadaş");

        // ...and taking its name is a constraint failure, not a silent merge.
        assert!(
            update_username(&conn, user_id, "arkadas").is_err(),
            "a rename onto a taken username must be refused"
        );
        assert_eq!(
            find_user_by_id(&conn, user_id)?.map(|user| user.username),
            Some("yeni-ad".to_owned()),
            "a refused rename must leave the account where it was"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// Changing a password ends every session the account holds, and only that
    /// account's: a session opened with the old password must not keep working,
    /// and a neighbour signing in at the same moment must not be signed out.
    fn password_change_ends_only_that_account_sessions() -> Result<()> {
        let conn = pre_account_database()?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let user_id = create_user(&conn, "anon", "Anonim", &hash, None, "selam")?;
        let neighbour = create_user(&conn, "komsu", "Komsu", &hash, None, "selam")?;
        let expires_at = chrono::Utc::now().timestamp() + 3600;
        create_user_session(&conn, "own-one", user_id, expires_at)?;
        create_user_session(&conn, "own-two", user_id, expires_at)?;
        create_user_session(&conn, "theirs", neighbour, expires_at)?;

        assert_eq!(delete_user_sessions_for_user(&conn, user_id)?, 2);
        assert!(
            get_user_session(&conn, "own-one")?.is_none(),
            "a session opened with the replaced password must not survive it"
        );
        assert!(
            get_user_session(&conn, "own-two")?.is_none(),
            "every session of that account is ended, not just the newest one"
        );
        assert!(
            get_user_session(&conn, "theirs")?.is_some(),
            "another account's session is none of this one's business"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A role and a state are read back exactly as written, and an account
    /// without them reads back as the least authority rather than as a hole.
    fn roles_and_states_round_trip() -> Result<()> {
        let conn = pre_account_database()?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let user_id = create_user(&conn, "anon", "Anonim", &hash, None, "")?;

        let fresh = find_user_by_id(&conn, user_id)?.context("the account should exist")?;
        assert_eq!(fresh.role, UserRole::User, "a new account is a member");
        assert_eq!(fresh.status, AccountStatus::Active);
        assert!(fresh.can(crate::roles::Permission::Post));
        assert!(!fresh.can(crate::roles::Permission::AccessAdminPanel));

        set_user_role(&conn, user_id, UserRole::Moderator)?;
        let until = chrono::Utc::now().timestamp() + 600;
        set_user_status(&conn, user_id, AccountStatus::Suspended, Some(until))?;
        let staff = find_user_by_id(&conn, user_id)?.context("the account should exist")?;
        assert_eq!(staff.role, UserRole::Moderator);
        assert!(staff.effective_status(chrono::Utc::now().timestamp()) == AccountStatus::Suspended);
        assert!(
            staff.effective_status(until + 1) == AccountStatus::Active,
            "the suspension lifts on its own once its moment passes"
        );
        assert!(staff.can(crate::roles::Permission::AccessAdminPanel));
        assert!(!staff.can(crate::roles::Permission::AssignRoles));

        set_user_role(&conn, user_id, UserRole::Owner)?;
        set_user_status(&conn, user_id, AccountStatus::Banned, None)?;
        let banned = find_user_by_id(&conn, user_id)?.context("the account should exist")?;
        assert_eq!(banned.role, UserRole::Owner);
        assert!(!banned.effective_status(0).may_sign_in());
        assert_eq!(banned.badge(0), crate::roles::RoleBadge::Banned);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A name this build does not recognise resolves to the least authority, so
    /// a damaged row cannot promote itself into the administration panel.
    fn an_unreadable_role_column_is_not_authority() -> Result<()> {
        let conn = pre_account_database()?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let user_id = create_user(&conn, "anon", "Anonim", &hash, None, "")?;
        conn.execute("UPDATE users SET role = 'root' WHERE id = ?1", [user_id])?;

        let account = find_user_by_id(&conn, user_id)?.context("the account should exist")?;
        assert_eq!(account.role, UserRole::User);
        assert!(
            !account.role.reaches_admin_panel(),
            "an unknown stored role must not reach the administration panel"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// The listing and the search both read accounts back, and the search finds
    /// an account by either of its two names.
    fn the_listing_and_search_find_accounts() -> Result<()> {
        let conn = pre_account_database()?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let first = create_user(&conn, "anon", "Anonim", &hash, None, "")?;
        create_user(&conn, "komsu", "Komsu", &hash, None, "")?;

        assert_eq!(list_users(&conn, 25, 0)?.len(), 2);
        assert_eq!(list_users(&conn, 25, 2)?.len(), 0, "an offset past the end lists nothing");
        assert_eq!(search_users(&conn, "kom", 25)?.len(), 1);
        assert_eq!(
            search_users(&conn, "anon", 25)?[0].id,
            first,
            "a search matches the username as well as the display name"
        );
        assert!(search_users(&conn, "yok-boyle-bir-hesap", 25)?.is_empty());
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// A share is named after the account the post is linked to, and a post
    /// that belongs to nobody is named after nobody. The name typed into the
    /// form is free text and is not read here at all, so it cannot put a share
    /// in another account's name — which is the whole point: a share is a
    /// claim about who posted, and only the account row can support one.
    fn a_share_is_named_after_the_account_behind_the_post() -> Result<()> {
        let conn = pre_account_database()?;
        normalize_database_schema_version(&conn)?;
        let hash = crate::utils::crypto::hash_password("Hunter2Hunter2")?;
        let user_id = create_user(&conn, "anon", "Anonim", &hash, None, "")?;
        let other_id = create_user(&conn, "komsu", "Komsu", &hash, None, "")?;
        let thread_id: i64 = conn.query_row("SELECT id FROM threads", [], |row| row.get(0))?;

        let insert = |name: &str| -> Result<i64> {
            Ok(conn.query_row(
                "INSERT INTO posts (thread_id, board_id, name, body, body_html, deletion_token)
                 VALUES (?1, 1, ?2, 'gonderi', '<p>gonderi</p>', 'token') RETURNING id",
                params![thread_id, name],
                |row| row.get(0),
            )?)
        };
        // The typed name spells out somebody else's account, and the post
        // belongs to nobody: nothing may be claimed from that name.
        let unlinked = insert("Komsu")?;
        let linked = insert("Komsu")?;
        let neighbour = insert("anon")?;
        super::link_post_to_account(&conn, linked, user_id)?;
        super::link_post_to_account(&conn, neighbour, other_id)?;

        let authors = super::post_share_authors(&conn, &[unlinked, linked, neighbour])?;
        assert!(
            !authors.contains_key(&unlinked),
            "a post that belongs to no account has nobody to attribute a share to"
        );
        assert_eq!(
            authors.get(&linked).map(String::as_str),
            Some("anon"),
            "a share is named after the account behind the post, not the typed name"
        );
        assert_eq!(
            authors.get(&neighbour).map(String::as_str),
            Some("komsu"),
            "each post is named after its own account"
        );
        assert!(
            super::post_share_authors(&conn, &[])?.is_empty(),
            "a page with no posts asks for no names"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    /// The board profile of the first operator is given ownership once, and a
    /// site that already appointed an owner keeps them.
    fn the_first_operator_becomes_the_site_owner() -> Result<()> {
        let conn = pre_account_database()?;
        ensure_owner_profile(&conn)?;

        let owner = find_user_by_username(&conn, "admin")?.context("the operator should have a profile")?;
        assert_eq!(owner.role, UserRole::Owner);
        assert_eq!(super::count_users_with_role(&conn, UserRole::Owner)?, 1);

        // A second call is a no-op rather than a second promotion.
        ensure_owner_profile(&conn)?;
        assert_eq!(super::count_users_with_role(&conn, UserRole::Owner)?, 1);
        Ok(())
    }
}
