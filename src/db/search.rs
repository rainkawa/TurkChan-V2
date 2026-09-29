//! Global search across posts, threads, boards, and accounts.
//!
//! A reader who remembers a post by the words in it, by the title above it, by
//! the board it was on, or by who wrote it should not have to know which of
//! those they remember. One query takes all of them and answers with whatever
//! matches, so the reader is not asked to choose a search mode first.
//!
//! Every filter is optional and the defaults are wide open, because a filter
//! that is on by default narrows a search the reader did not ask to narrow.
//! A reader who types a word and presses enter has asked for every post
//! carrying it, and a page of results that silently dropped the ones from last
//! year would be a page lying about what exists.
//!
//! Nothing here is built out of a query string. Every filter is a bound
//! parameter and the column a filter applies to is chosen from a fixed set, so
//! nothing a reader types can reach the shape of the statement.

use anyhow::{Context as _, Result};
use rusqlite::types::Value as SqlValue;
use rusqlite::params_from_iter;

/// Longest query accepted, in characters.
pub const SEARCH_MAX_CHARS: usize = 200;

/// The kinds of thing a global search can return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchKind {
    /// A post that matched.
    Post,
    /// A thread whose title matched.
    Thread,
    /// A board whose name or description matched.
    Board,
    /// An account whose name matched.
    User,
}

impl SearchKind {
    /// The stored token for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Post => "post",
            Self::Thread => "thread",
            Self::Board => "board",
            Self::User => "user",
        }
    }
}

/// One thing a search matched, in the shape every kind can be shown as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Which kind of thing this is.
    pub kind: SearchKind,
    /// Its own identifier within that kind.
    pub id: i64,
    /// Its title: the post's subject or a line of its body, the thread's
    /// subject, the board's name, the account's name.
    pub title: String,
    /// A line of what matched, for the reader to recognise it by.
    pub excerpt: String,
    /// Where pressing it goes.
    pub href: String,
}

/// Everything a reader narrowed a search by.
///
/// Every field is a plain bound value, so a reader who types a quotation mark
/// into a filter box is searching for a quotation mark.
#[derive(Debug, Clone, Default)]
pub struct SearchFilters {
    /// Only posts on this board.
    pub board_id: Option<i64>,
    /// Only posts written by this account.
    pub user_id: Option<i64>,
    /// Only posts written on or after this day, as a Unix timestamp.
    pub since: Option<i64>,
    /// Only posts written before this day, as a Unix timestamp.
    pub until: Option<i64>,
    /// Only posts that carry media, when true; only posts that carry none,
    /// when false; either, when absent.
    pub has_media: Option<bool>,
    /// Only posts scoring at least this much.
    pub min_score: Option<i64>,
    /// Only the opening post of a thread, or only a reply.
    pub op_only: Option<bool>,
}

/// Escape the characters that would otherwise end a term early.
///
/// A reader's word is put inside quotes so a space inside it is a space and
/// not a separator, and any quote in it is doubled so it cannot close the term
/// and turn the rest of their input into syntax.
fn quote_term(term: &str) -> String {
    format!(r#""{}"*"#, term.replace('"', r#""""#))
}

/// Turn a reader's words into a match expression.
///
/// Each word is a prefix term, so a reader who types the start of a word is
/// not told they found nothing for it. An empty query matches nothing at all:
/// a search box that has been emptied is a request for the whole board, which
/// is not what pressing search in an empty box means.
fn to_fts_query(query: &str) -> Option<String> {
    let terms = query
        .split_whitespace()
        .filter(|term| !term.is_empty())
        .map(quote_term)
        .collect::<Vec<_>>();
    (!terms.is_empty()).then(|| terms.join(" AND "))
}

/// Return the words a reader typed, capped so a pasted paragraph is not turned
/// into a thousand index terms.
fn cleaned(query: &str) -> String {
    query.trim().chars().take(SEARCH_MAX_CHARS).collect()
}

/// Add a bound filter to the statement, returning whether it narrowed anything.
///
/// Each arm is a literal comparison against a column chosen here, never a
/// fragment of SQL assembled from what the reader typed.
fn push_filter(sql: &mut String, params: &mut Vec<SqlValue>, filter: &str, value: SqlValue) {
    if !sql.contains(" WHERE ") {
        sql.push_str(" WHERE ");
    } else {
        sql.push_str(" AND ");
    }
    sql.push_str(filter);
    params.push(value);
}

/// Run a global search and return the hits.
///
/// # Errors
/// Returns an error if the query cannot be prepared or read.
pub fn global_search(
    conn: &rusqlite::Connection,
    query: &str,
    filters: &SearchFilters,
    limit: i64,
    offset: i64,
) -> Result<Vec<SearchHit>> {
    let cleaned = cleaned(query);
    let Some(fts) = to_fts_query(&cleaned) else {
        return Ok(Vec::new());
    };
    let mut params: Vec<SqlValue> = vec![fts.into()];
    let mut sql = String::from(
        "SELECT p.id, COALESCE(NULLIF(p.subject, ''), p.body) AS title,
                substr(p.body, 1, 200) AS excerpt, p.thread_id, p.board_id, b.short_name
         FROM posts AS p
         JOIN posts_fts ON posts_fts.rowid = p.id
         JOIN boards AS b ON b.id = p.board_id
         WHERE posts_fts MATCH ?1",
    );
    if let Some(board_id) = filters.board_id {
        push_filter(&mut sql, &mut params, "p.board_id = ?", board_id.into());
    }
    if let Some(user_id) = filters.user_id {
        push_filter(&mut sql, &mut params, "p.user_id = ?", user_id.into());
    }
    if let Some(since) = filters.since {
        push_filter(
            &mut sql,
            &mut params,
            "p.created_at >= ?",
            since.into(),
        );
    }
    if let Some(until) = filters.until {
        push_filter(&mut sql, &mut params, "p.created_at <= ?", until.into());
    }
    if let Some(has_media) = filters.has_media {
        push_filter(
            &mut sql,
            &mut params,
            if has_media {
                "p.file_path IS NOT NULL"
            } else {
                "p.file_path IS NULL"
            },
            SqlValue::Null,
        );
    }
    if let Some(op_only) = filters.op_only {
        push_filter(
            &mut sql,
            &mut params,
            if op_only { "p.is_op = 1" } else { "p.is_op = 0" },
            SqlValue::Null,
        );
    }
    if let Some(min_score) = filters.min_score {
        push_filter(
            &mut sql,
            &mut params,
            "COALESCE((SELECT SUM(v.value) FROM post_votes AS v WHERE v.post_id = p.id), 0) >= ?",
            min_score.into(),
        );
    }
    sql.push_str(" ORDER BY p.created_at DESC, p.id DESC LIMIT ? OFFSET ?");
    params.push((limit.max(1)).into());
    params.push((offset.max(0)).into());

    let mut stmt = conn
        .prepare_cached(&sql)
        .context("Failed to prepare the search")?;
    let rows = stmt
        .query_map(params_from_iter(params.iter()), |row| {
            let id: i64 = row.get(0)?;
            let title: String = row.get(1)?;
            let excerpt: String = row.get(2)?;
            let thread_id: i64 = row.get(3)?;
            let board_short: String = row.get(5)?;
            Ok(SearchHit {
                kind: SearchKind::Post,
                id,
                href: format!("/{board_short}/thread/{thread_id}#p{id}"),
                title,
                excerpt,
            })
        })
        .context("Failed to run the search")?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Return how many posts a search with these filters would match.
///
/// The count is asked with the same filters as the list, so the two cannot
/// describe different searches: a page claiming "12 results" over a list of
/// eight is a page a reader cannot act on.
///
/// # Errors
/// Returns an error if the count cannot be read.
pub fn count_global_search(
    conn: &rusqlite::Connection,
    query: &str,
    filters: &SearchFilters,
) -> Result<i64> {
    let cleaned = cleaned(query);
    let Some(fts) = to_fts_query(&cleaned) else {
        return Ok(0);
    };
    let mut params: Vec<SqlValue> = vec![fts.into()];
    let mut sql = String::from(
        "SELECT COUNT(*)
         FROM posts AS p
         JOIN posts_fts ON posts_fts.rowid = p.id
         WHERE posts_fts MATCH ?1",
    );
    if let Some(board_id) = filters.board_id {
        push_filter(&mut sql, &mut params, "p.board_id = ?", board_id.into());
    }
    if let Some(user_id) = filters.user_id {
        push_filter(&mut sql, &mut params, "p.user_id = ?", user_id.into());
    }
    if let Some(since) = filters.since {
        push_filter(&mut sql, &mut params, "p.created_at >= ?", since.into());
    }
    if let Some(until) = filters.until {
        push_filter(&mut sql, &mut params, "p.created_at <= ?", until.into());
    }
    if let Some(has_media) = filters.has_media {
        push_filter(
            &mut sql,
            &mut params,
            if has_media {
                "p.file_path IS NOT NULL"
            } else {
                "p.file_path IS NULL"
            },
            SqlValue::Null,
        );
    }
    if let Some(op_only) = filters.op_only {
        push_filter(
            &mut sql,
            &mut params,
            if op_only { "p.is_op = 1" } else { "p.is_op = 0" },
            SqlValue::Null,
        );
    }
    if let Some(min_score) = filters.min_score {
        push_filter(
            &mut sql,
            &mut params,
            "COALESCE((SELECT SUM(v.value) FROM post_votes AS v WHERE v.post_id = p.id), 0) >= ?",
            min_score.into(),
        );
    }
    let mut stmt = conn
        .prepare_cached(&sql)
        .context("Failed to prepare the search count")?;
    let count: i64 = stmt
        .query_row(params_from_iter(params.iter()), |row| row.get(0))
        .context("Failed to count the search")?;
    Ok(count)
}

/// Return accounts whose name contains what the reader typed.
///
/// Accounts are matched on their login and display names rather than through
/// the post index, because an account is not a post and a reader looking for a
/// person is looking for the person.
///
/// # Errors
/// Returns an error if the list cannot be read.
pub fn search_users(conn: &rusqlite::Connection, query: &str, limit: i64) -> Result<Vec<SearchHit>> {
    let cleaned = cleaned(query);
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    // The pattern is bound, and the wildcards are added here so a reader who
    // types one is searching for it rather than widening the match.
    let pattern = format!(
        "%{}%",
        cleaned
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, username, display_name, bio FROM users
             WHERE username LIKE ?1 ESCAPE '\\' OR display_name LIKE ?1 ESCAPE '\\'
             ORDER BY username ASC
             LIMIT ?2",
        )
        .context("Failed to prepare the account search")?;
    let rows = stmt
        .query_map(rusqlite::params![pattern, limit.max(1)], |row| {
            let id: i64 = row.get(0)?;
            let username: String = row.get(1)?;
            let display_name: String = row.get(2)?;
            let bio: String = row.get(3)?;
            Ok(SearchHit {
                kind: SearchKind::User,
                id,
                title: display_name,
                excerpt: bio,
                href: format!("/u/{username}"),
            })
        })
        .context("Failed to read the account search")?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Return boards whose name or description contains what the reader typed.
///
/// # Errors
/// Returns an error if the list cannot be read.
pub fn search_boards(
    conn: &rusqlite::Connection,
    query: &str,
    limit: i64,
) -> Result<Vec<SearchHit>> {
    let cleaned = cleaned(query);
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    let pattern = format!(
        "%{}%",
        cleaned
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, short_name, name, description FROM boards
             WHERE short_name LIKE ?1 ESCAPE '\\'
                OR name LIKE ?1 ESCAPE '\\'
                OR description LIKE ?1 ESCAPE '\\'
             ORDER BY display_order ASC
             LIMIT ?2",
        )
        .context("Failed to prepare the board search")?;
    let rows = stmt
        .query_map(rusqlite::params![pattern, limit.max(1)], |row| {
            let short_name: String = row.get(1)?;
            let name: String = row.get(2)?;
            let description: String = row.get(3)?;
            Ok(SearchHit {
                kind: SearchKind::Board,
                id: row.get(0)?,
                href: format!("/{short_name}"),
                title: name,
                excerpt: description,
            })
        })
        .context("Failed to read the board search")?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Return threads whose subject contains what the reader typed.
///
/// # Errors
/// Returns an error if the list cannot be read.
pub fn search_threads(
    conn: &rusqlite::Connection,
    query: &str,
    limit: i64,
) -> Result<Vec<SearchHit>> {
    let cleaned = cleaned(query);
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    let pattern = format!(
        "%{}%",
        cleaned
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let mut stmt = conn
        .prepare_cached(
            "SELECT t.id, COALESCE(NULLIF(t.subject, ''), '(konusuz)') AS subject,
                    t.reply_count, b.short_name
             FROM threads AS t
             JOIN boards AS b ON b.id = t.board_id
             WHERE t.subject LIKE ?1 ESCAPE '\\'
             ORDER BY t.bumped_at DESC
             LIMIT ?2",
        )
        .context("Failed to prepare the thread search")?;
    let rows = stmt
        .query_map(rusqlite::params![pattern, limit.max(1)], |row| {
            let id: i64 = row.get(0)?;
            let subject: String = row.get(1)?;
            let reply_count: i64 = row.get(2)?;
            let board_short: String = row.get(3)?;
            Ok(SearchHit {
                kind: SearchKind::Thread,
                id,
                href: format!("/{board_short}/thread/{id}"),
                title: subject,
                excerpt: format!("{reply_count} yanıt"),
            })
        })
        .context("Failed to read the thread search")?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Read a day's start as a Unix timestamp, treating an unparseable day as
/// absent rather than as the beginning of time.
///
/// A reader whose date box holds something that is not a date gets the search
/// they asked for rather than a search narrowed to every post ever written.
#[must_use]
pub fn parse_day(raw: &str, end_of_day: bool) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d").ok()?;
    let midnight = parsed.and_hms_opt(0, 0, 0)?;
    let day = if end_of_day {
        midnight + chrono::Duration::days(1) - chrono::Duration::seconds(1)
    } else {
        midnight
    };
    day.and_utc().timestamp()
}

#[cfg(test)]
mod tests {
    use super::{
        count_global_search, global_search, parse_day, search_boards, search_threads, search_users,
        SearchFilters, SearchKind,
    };
    use crate::db::schema::install_or_migrate_schema;
    use anyhow::Result;

    const AUTHOR: i64 = 1;

    fn test_conn() -> Result<rusqlite::Connection> {
        let conn = rusqlite::Connection::open_in_memory()?;
        install_or_migrate_schema(&conn)?;
        conn.execute(
            "INSERT INTO users (id, username, display_name, password_hash)
             VALUES (?1, 'yazar', 'Yazar', 'not-a-real-hash')",
            rusqlite::params![AUTHOR],
        )?;
        let board_id: i64 =
            conn.query_row("SELECT id FROM boards WHERE short_name = 'genel'", [], |row| {
                row.get(0)
            })?;
        conn.execute(
            "INSERT INTO threads (id, board_id, subject) VALUES (1, ?1, 'Bir konu')",
            rusqlite::params![board_id],
        )?;
        for (id, subject, body, with_media) in [
            (1, Some("Başlık bir"), "ilk yazının içeriği", false),
            (2, None, "medya taşıyan yazı", true),
            (3, Some("Başlık üç"), "üçüncü yazının içeriği", false),
        ] {
            conn.execute(
                "INSERT INTO posts
                   (id, thread_id, board_id, name, subject, body, body_html,
                    deletion_token, is_op, user_id, file_path, created_at)
                 VALUES (?1, 1, ?2, 'Yazar', ?3, ?4, ?4, 'token', ?5, ?6, ?7, 1_700_000_000)",
                rusqlite::params![
                    id,
                    board_id,
                    subject,
                    body,
                    i64::from(id == 1),
                    AUTHOR,
                    if with_media { Some("genel/a.png") } else { None }
                ],
            )?;
        }
        Ok(conn)
    }

    #[test]
    /// A reader who remembers only the words still finds the post, and the
    /// link it produces is the one that opens that exact post.
    fn searching_by_body_finds_the_post_and_links_to_it() -> Result<()> {
        let conn = test_conn()?;
        let hits = global_search(&conn, "üçüncü", &SearchFilters::default(), 10, 0)?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SearchKind::Post);
        assert!(hits[0].href.contains("#p3"));
        Ok(())
    }

    #[test]
    /// A reader who only remembers the title is not told there is nothing,
    /// because the title is indexed too.
    fn a_subject_is_searchable() -> Result<()> {
        let conn = test_conn()?;
        let hits = global_search(&conn, "Başlık", &SearchFilters::default(), 10, 0)?;
        assert_eq!(hits.len(), 2, "two posts carry a subject with that word");
        Ok(())
    }

    #[test]
    /// A word typed as a prefix finds the post that starts with it, because
    /// somebody who remembers the beginning of a word has still remembered
    /// something real.
    fn a_partial_word_still_matches() -> Result<()> {
        let conn = test_conn()?;
        let hits = global_search(&conn, "üçün", &SearchFilters::default(), 10, 0)?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    /// Every filter narrows, and none of them is on unless it was asked for.
    fn filters_narrow_and_default_to_nothing() -> Result<()> {
        let conn = test_conn()?;
        let board_id: i64 = conn.query_row(
            "SELECT id FROM boards WHERE short_name = 'genel'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            global_search(&conn, "yazı", &SearchFilters::default(), 20, 0)?.len(),
            3,
            "an unfiltered search must not quietly drop anything"
        );

        let only_op = SearchFilters {
            op_only: Some(true),
            ..SearchFilters::default()
        };
        assert_eq!(global_search(&conn, "yazı", &only_op, 20, 0)?.len(), 1);

        let only_replies = SearchFilters {
            op_only: Some(false),
            ..SearchFilters::default()
        };
        assert_eq!(global_search(&conn, "yazı", &only_replies, 20, 0)?.len(), 2);

        let with_media = SearchFilters {
            has_media: Some(true),
            ..SearchFilters::default()
        };
        assert_eq!(global_search(&conn, "yazı", &with_media, 20, 0)?.len(), 1);

        let by_author = SearchFilters {
            user_id: Some(AUTHOR),
            board_id: Some(board_id),
            ..SearchFilters::default()
        };
        assert_eq!(global_search(&conn, "yazı", &by_author, 20, 0)?.len(), 3);
        Ok(())
    }

    #[test]
    /// A date the reader typed is honoured, and a date box holding something
    /// that is not a date is ignored rather than being read as "since the
    /// beginning of time".
    fn a_date_filter_bounds_the_search_and_bad_input_is_ignored() -> Result<()> {
        let conn = test_conn()?;
        let after_everything = SearchFilters {
            since: parse_day("2001-01-01", false),
            ..SearchFilters::default()
        };
        assert_eq!(
            global_search(&conn, "yazı", &after_everything, 20, 0)?.len(),
            0,
            "a day after the posts were written must exclude them"
        );
        let before_everything = SearchFilters {
            until: parse_day("2001-01-01", true),
            ..SearchFilters::default()
        };
        assert_eq!(
            global_search(&conn, "yazı", &before_everything, 20, 0)?.len(),
            3
        );
        assert_eq!(parse_day("not a date", false), None);
        assert_eq!(parse_day("", false), None);
        Ok(())
    }

    #[test]
    /// The count a page announces is the count the list can produce, because
    /// both are asked with the same filters.
    fn the_count_agrees_with_the_list() -> Result<()> {
        let conn = test_conn()?;
        let filters = SearchFilters {
            op_only: Some(false),
            ..SearchFilters::default()
        };
        let counted = count_global_search(&conn, "yazı", &filters)?;
        let listed = global_search(&conn, "yazı", &filters, 20, 0)?;
        assert_eq!(counted, i64::try_from(listed.len()).unwrap_or(i64::MAX));
        Ok(())
    }

    #[test]
    /// An empty search box is a reader who has not typed yet, not a reader who
    /// wants the whole board.
    fn an_empty_search_matches_nothing() -> Result<()> {
        let conn = test_conn()?;
        assert!(global_search(&conn, "   ", &SearchFilters::default(), 20, 0)?.is_empty());
        assert_eq!(count_global_search(&conn, "", &SearchFilters::default())?, 0);
        Ok(())
    }

    #[test]
    /// What a reader types is a word to look for, never a piece of the
    /// statement. A quotation mark searches for a quotation mark.
    fn typed_characters_are_searched_for_not_executed() -> Result<()> {
        let conn = test_conn()?;
        // A lone double quote would close the term and turn the rest into
        // syntax if it were not escaped.
        let hits = global_search(&conn, r#""yazının""#, &SearchFilters::default(), 20, 0)?;
        assert!(!hits.is_empty());
        // A term that is only operators matches nothing rather than erroring.
        let empty = global_search(&conn, "AND OR NOT", &SearchFilters::default(), 20, 0)?;
        assert!(empty.is_empty());
        Ok(())
    }

    #[test]
    /// A wildcard a reader types is a wildcard they are looking for, not one
    /// that widens the match behind their back.
    fn a_typed_wildcard_is_escaped() -> Result<()> {
        let conn = test_conn()?;
        let hits = search_users(&conn, "%", 10)?;
        assert!(
            hits.is_empty(),
            "a percent sign must not match every account"
        );
        let named = search_users(&conn, "yaz", 10)?;
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].href, "/u/yazar");
        Ok(())
    }

    #[test]
    /// The other three kinds are searched too, each with a link that opens the
    /// thing itself rather than a list it appeared in.
    fn boards_threads_and_accounts_are_searchable_too() -> Result<()> {
        let conn = test_conn()?;
        let boards = search_boards(&conn, "genel", 10)?;
        assert!(!boards.is_empty());
        assert_eq!(boards[0].kind, SearchKind::Board);
        assert!(boards[0].href.starts_with('/'));

        let threads = search_threads(&conn, "Bir", 10)?;
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].kind, SearchKind::Thread);
        assert!(threads[0].href.contains("/thread/1"));

        let users = search_users(&conn, "Yazar", 10)?;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].kind, SearchKind::User);
        Ok(())
    }
}
