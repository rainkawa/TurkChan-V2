//! Public profile page for an anonymous board account.
//!
//! The page follows the shared document layout, so the site chrome, theme
//! picker, and header account menu behave exactly as they do on a board. Only
//! the body is new: a header with the account's avatar, chosen names, and
//! score, followed by tabbed history of everything the account wrote.
//!
//! Nothing here exposes more than the account already publishes on a board:
//! the display name, the unique username, the self-description, the join date,
//! and the account's own posts. There is no field for a real name, an address,
//! or any other identifying detail.

use std::collections::HashMap;

use crate::models::{Board, Pagination, ProfilePost, ProfileStats, ProfileThread, User};
use crate::templates::{fmt_ts_short, UserPreferences};
use crate::utils::sanitize::{escape_html, render_post_excerpt};

/// One profile tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileTab {
    /// Everything the account wrote.
    Posts,
    /// Threads the account opened.
    Threads,
    /// Replies the account wrote, without its own opening posts.
    Replies,
}

impl ProfileTab {
    /// Resolve a tab from a query value, defaulting to the full history.
    #[must_use]
    pub fn from_query(value: Option<&str>) -> Self {
        match value {
            Some("threads") | Some("konular") => Self::Threads,
            Some("replies") | Some("yanitlar") => Self::Replies,
            _ => Self::Posts,
        }
    }

    /// Value carried in the tab's query string.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Posts => "posts",
            Self::Threads => "threads",
            Self::Replies => "replies",
        }
    }

    /// Visible tab label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Posts => "Gönderiler",
            Self::Threads => "Konular",
            Self::Replies => "Yanıtlar",
        }
    }

    /// Every tab in display order.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Posts, Self::Threads, Self::Replies]
    }

    /// How many records this tab counts for the badge on the tab strip.
    #[must_use]
    pub const fn count(self, stats: &ProfileStats) -> i64 {
        match self {
            Self::Posts => stats.post_count,
            Self::Threads => stats.thread_count,
            Self::Replies => stats.reply_count,
        }
    }
}

/// Return the excerpt of a post with its `>>N` references already linked.
///
/// `referenced_boards` maps a referenced post id to the board that owns it, so
/// a reference still lands on the right thread from a page that is not that
/// thread. A reference to a post that no longer exists stays plain text.
fn post_excerpt(body: &str, referenced_boards: &HashMap<i64, String>) -> String {
    render_post_excerpt(&escape_html(body), |post_id| {
        referenced_boards
            .get(&post_id)
            .map(|board| format!("/{board}/post/{post_id}"))
    })
}

/// Render the tab strip, marking the active tab for assistive technology.
fn render_tabs(username: &str, active: ProfileTab, stats: &ProfileStats) -> String {
    let mut html = String::from(r#"<nav class="profile-tabs" aria-label="Profil sekmeleri">"#);
    for tab in ProfileTab::all() {
        let class = if tab == active {
            r#" class="profile-tab is-active""#
        } else {
            r#" class="profile-tab""#
        };
        let current = if tab == active {
            r#" aria-current="page""#
        } else {
            ""
        };
        html.push_str(&format!(
            r#"<a{class} href="/u/{username}?tab={slug}"{current}>{label} <span class="profile-tab-count">{count}</span></a>"#,
            class = class,
            current = current,
            username = escape_html(username),
            slug = tab.slug(),
            label = tab.label(),
            count = tab.count(stats),
        ));
    }
    html.push_str("</nav>");
    html
}

/// Render the header with the avatar, names, description, and score.
fn render_header(account: &User, stats: &ProfileStats) -> String {
    let bio = if account.bio.trim().is_empty() {
        r#"<p class="profile-bio is-empty">bu hesap henüz bir açıklama eklememiş.</p>"#.to_owned()
    } else {
        format!(
            r#"<p class="profile-bio">{}</p>"#,
            escape_html(account.bio.trim())
        )
    };
    format!(
        r#"<header class="profile-header">
<img class="profile-avatar" src="/auth/avatar/{user_id}" width="96" height="96" alt="{alt}">
<div class="profile-identity">
<h1 class="profile-name">{display_name}</h1>
<p class="profile-handle">@{username}</p>
{bio}
<p class="profile-joined">Katıldı: {created_at}</p>
</div>
<div class="profile-score">
<span class="profile-score-value">{karma}</span>
<span class="profile-score-label">beğeni puanı</span>
</div>
</header>"#,
        user_id = account.id,
        alt = escape_html(&account.display_name),
        display_name = escape_html(&account.display_name),
        username = escape_html(&account.username),
        bio = bio,
        created_at = escape_html(&fmt_ts_short(account.created_at)),
        karma = stats.karma,
    )
}

/// Render one post of the account's history.
fn render_post_entry(
    post: &ProfilePost,
    referenced_boards: &HashMap<i64, String>,
) -> String {
    let board = escape_html(&post.board_short);
    let subject = post.subject.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let subject_html = subject.map_or_else(String::new, |subject| {
        format!(
            r#"<h3 class="profile-entry-subject"><a href="/{board}/thread/{thread_id}#p{post_id}">{subject}</a></h3>"#,
            board = board,
            thread_id = post.thread_id,
            post_id = post.id,
            subject = escape_html(subject),
        )
    });
    let op_badge = if post.is_op {
        r#"<span class="profile-entry-badge">konu açığı</span>"#
    } else {
        ""
    };
    format!(
        r#"<article class="profile-entry">
<p class="profile-entry-meta"><a class="profile-entry-board" href="/{board}/">/{board}/</a>{op_badge}<span class="profile-entry-time">{created_at}</span></p>
{subject_html}
<div class="profile-entry-body">{body}</div>
<p class="profile-entry-actions"><a class="profile-entry-link" href="/{board}/thread/{thread_id}#p{post_id}">gönderiye git</a><a class="profile-entry-link" href="/{board}/">boarda git</a></p>
</article>"#,
        board = board,
        op_badge = op_badge,
        created_at = escape_html(&fmt_ts_short(post.created_at)),
        subject_html = subject_html,
        body = post_excerpt(&post.body, referenced_boards),
        thread_id = post.thread_id,
        post_id = post.id,
    )
}

/// Render one thread the account opened.
fn render_thread_entry(
    thread: &ProfileThread,
    referenced_boards: &HashMap<i64, String>,
) -> String {
    let board = escape_html(&thread.board_short);
    let subject = thread
        .subject
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("konu");
    format!(
        r#"<article class="profile-entry">
<p class="profile-entry-meta"><a class="profile-entry-board" href="/{board}/">/{board}/</a><span class="profile-entry-badge">{replies} yanıt</span><span class="profile-entry-time">{created_at}</span></p>
<h3 class="profile-entry-subject"><a href="/{board}/thread/{thread_id}#p{post_id}">{subject}</a></h3>
<div class="profile-entry-body">{body}</div>
<p class="profile-entry-actions"><a class="profile-entry-link" href="/{board}/thread/{thread_id}#p{post_id}">konuya git</a><a class="profile-entry-link" href="/{board}/">boarda git</a></p>
</article>"#,
        board = board,
        replies = thread.reply_count,
        created_at = escape_html(&fmt_ts_short(thread.created_at)),
        subject = escape_html(subject),
        thread_id = thread.thread_id,
        post_id = thread.post_id,
        body = post_excerpt(&thread.body, referenced_boards),
    )
}

/// Message shown when the selected tab has nothing to list yet.
fn render_empty(tab: ProfileTab) -> String {
    let message = match tab {
        ProfileTab::Posts => "henüz gönderi yok.",
        ProfileTab::Threads => "henüz konu açmamış.",
        ProfileTab::Replies => "henüz yanıt yazmamış.",
    };
    format!(r#"<p class="profile-empty">{message}</p>"#)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the profile page renders the header, tab strip, and one history listing together"
)]
/// Renders a public account profile.
///
/// `referenced_boards` resolves the `>>N` references inside the listed excerpts
/// to the board that owns the referenced post, and `account_menu_html` is the
/// pre-rendered header menu the shared layout embeds.
#[must_use]
pub fn profile_page(
    account: &User,
    stats: &ProfileStats,
    tab: ProfileTab,
    posts: &[ProfilePost],
    threads: &[ProfileThread],
    referenced_boards: &HashMap<i64, String>,
    pagination: &Pagination,
    boards: &[Board],
    current_theme: Option<&str>,
    user_preferences: UserPreferences,
    csrf_token: &str,
    account_menu_html: &str,
) -> String {
    let mut feed = String::new();
    match tab {
        ProfileTab::Threads => {
            for thread in threads {
                feed.push_str(&render_thread_entry(thread, referenced_boards));
            }
        }
        ProfileTab::Posts | ProfileTab::Replies => {
            for post in posts {
                feed.push_str(&render_post_entry(post, referenced_boards));
            }
        }
    }
    if feed.is_empty() {
        feed.push_str(&render_empty(tab));
    }
    feed.push_str(&crate::templates::render_pagination(
        pagination,
        &format!("/u/{}?tab={}", account.username, tab.slug()),
    ));

    let body = format!(
        r#"<div class="profile-page">
{render_header}
{tabs}
<section class="profile-feed">{feed}</section>
</div>"#,
        render_header = render_header(account, stats),
        tabs = render_tabs(&account.username, tab, stats),
        feed = feed,
    );

    crate::templates::base_layout_with_account(
        &format!("@{} - Profil", account.username),
        None,
        &body,
        csrf_token,
        boards,
        current_theme,
        None,
        false,
        &format!("/u/{}", account.username),
        user_preferences,
        account_menu_html,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{profile_page, ProfileTab};
    use crate::models::{Pagination, ProfilePost, ProfileStats, ProfileThread, User};
    use crate::templates::UserPreferences;

    fn account() -> User {
        User {
            id: 7,
            username: "anon".to_owned(),
            display_name: "Anonim".to_owned(),
            password_hash: "hash".to_owned(),
            avatar_file: None,
            bio: "selam".to_owned(),
            karma: 3,
            created_at: 1_700_000_000,
        }
    }

    fn stats() -> ProfileStats {
        ProfileStats {
            thread_count: 1,
            post_count: 2,
            reply_count: 1,
            karma: 3,
        }
    }

    fn posts() -> Vec<ProfilePost> {
        vec![ProfilePost {
            id: 5,
            thread_id: 4,
            board_short: "g".to_owned(),
            subject: Some("Konu".to_owned()),
            body: ">>1 selam".to_owned(),
            is_op: true,
            created_at: 1_700_000_000,
        }]
    }

    fn threads() -> Vec<ProfileThread> {
        vec![ProfileThread {
            thread_id: 4,
            post_id: 5,
            board_short: "g".to_owned(),
            subject: Some("Konu".to_owned()),
            body: "acilis".to_owned(),
            created_at: 1_700_000_000,
            reply_count: 1,
        }]
    }

    #[test]
    /// The page shows the chosen names, the description, the score, every tab,
    /// and a permalink back into the board the post belongs to.
    fn profile_page_renders_identity_score_tabs_and_permalinks() {
        let html = profile_page(
            &account(),
            &stats(),
            ProfileTab::Posts,
            &posts(),
            &threads(),
            &HashMap::new(),
            &Pagination::new(1, 10, 2),
            &[],
            None,
            UserPreferences::default(),
            "csrf",
            "",
        );

        assert!(html.contains("Anonim"));
        assert!(html.contains("@anon"));
        assert!(html.contains("selam"));
        assert!(html.contains(r#"<span class="profile-score-value">3</span>"#));
        assert!(html.contains(r#"href="/u/anon?tab=threads""#));
        assert!(html.contains(r#"href="/u/anon?tab=replies""#));
        assert!(html.contains(r#"href="/g/thread/4#p5""#));
        assert!(html.contains(r#"href="/g/""#));
        // A reference with no matching post stays plain text instead of
        // becoming a link that leads nowhere.
        assert!(html.contains("&gt;&gt;1 selam"));
    }

    #[test]
    /// The threads tab renders the account's own threads, and an account with
    /// no history says so instead of rendering an empty list.
    fn profile_page_switches_listing_per_tab() {
        let threads_html = profile_page(
            &account(),
            &stats(),
            ProfileTab::Threads,
            &[],
            &threads(),
            &HashMap::new(),
            &Pagination::new(1, 10, 1),
            &[],
            None,
            UserPreferences::default(),
            "csrf",
            "",
        );
        assert!(threads_html.contains("1 yanıt"));
        assert!(!threads_html.contains("&gt;&gt;1 selam"));

        let empty_html = profile_page(
            &account(),
            &stats(),
            ProfileTab::Replies,
            &[],
            &[],
            &HashMap::new(),
            &Pagination::new(1, 10, 0),
            &[],
            None,
            UserPreferences::default(),
            "csrf",
            "",
        );
        assert!(empty_html.contains("henüz yanıt yazmamış."));
    }
}
