//! Public profile page for an anonymous board account.
//!
//! The page follows the shared document layout, so the site chrome, theme
//! picker, and header account menu behave exactly as they do on a board. Only
//! the body is new: a header with the account's avatar, chosen names, score,
//! and account age, followed by tabbed history of everything the account
//! wrote.
//!
//! Nothing here exposes more than the account already publishes on a board:
//! the display name, the unique username, the self-description, the account's
//! age, and the account's own posts. There is no field for a real name, an
//! address, or any other identifying detail.

use std::collections::HashMap;

use crate::models::{Board, Pagination, ProfilePost, ProfileStats, ProfileThread, User};
use crate::templates::{fmt_ts_short, UserPreferences};
use crate::utils::sanitize::{escape_html, render_post_excerpt};
use chrono::{Datelike as _, TimeZone as _};

/// One profile tab.
///
/// A profile is read in two passes and no more: what the account published, and
/// what it said in somebody else's thread. A reply written under a thread
/// somebody else opened is a comment, so it belongs on the second tab even
/// though it is a post like any other — otherwise a commenter's own profile
/// would show them nothing but other people's threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileTab {
    /// Threads the account opened itself.
    Posts,
    /// Replies the account wrote, without its own opening posts.
    Replies,
}

impl ProfileTab {
    /// Resolve a tab from a query value, defaulting to what the account
    /// published.
    ///
    /// `threads` and `konular` are still accepted: they are what this tab was
    /// called before the two that are left, and a link somebody kept from
    /// then should not answer with the whole history.
    #[must_use]
    pub fn from_query(value: Option<&str>) -> Self {
        match value {
            Some("replies") | Some("yanitlar") => Self::Replies,
            _ => Self::Posts,
        }
    }

    /// Value carried in the tab's query string.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Posts => "posts",
            Self::Replies => "replies",
        }
    }

    /// Visible tab label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Posts => "Paylaşımlar",
            Self::Replies => "Yorumlar",
        }
    }

    /// Every tab in display order.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        [Self::Posts, Self::Replies]
    }

    /// How many records this tab counts for the badge on the tab strip.
    #[must_use]
    pub const fn count(self, stats: &ProfileStats) -> i64 {
        match self {
            Self::Posts => stats.thread_count,
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

/// Format how long an account has existed, in the words a person would use.
///
/// A creation date asks the reader to do the subtraction; "1 Yıl 3 Ay" is the
/// same fact already done. The two largest units are shown and the rest is
/// dropped, because "2 Yıl 8 Ay 14 Gün 3 saat" is a number only the account's
/// owner is interested in. A brand-new account reads as "Yeni" rather than as
/// "0 Gün", which is what a zero means to a reader and not what it means to a
/// calendar.
fn fmt_account_age(ts: i64) -> String {
    let Some(created) = chrono::Local.timestamp_opt(ts, 0).single() else {
        return "?".to_owned();
    };
    let now = chrono::Local::now();
    let mut years = now.year() - created.year();
    let mut months = i32::from(now.month()) - i32::from(created.month());
    // The day of the month is what decides the last, partial month: an account
    // born on the 30th is a month old on the 28th of the next month only if
    // that month is long enough, and borrowing thirty days is close enough for
    // a label that is already rounding.
    if now.day() < created.day() {
        months -= 1;
    }
    if months < 0 {
        years -= 1;
        months += 12;
    }
    match (years, months) {
        (0, 0) => "Yeni".to_owned(),
        (0, months) => format!("{months} Ay"),
        (years, 0) => format!("{years} Yıl"),
        (years, months) => format!("{years} Yıl {months} Ay"),
    }
}

/// Render a large count the way a feed shows one.
///
/// Past a thousand the exact digit stops being the point, and a five-digit
/// number in a three-column row is what pushes the row wider than a phone.
/// The value is still the real one; only its length is shortened.
fn fmt_compact_count(value: i64) -> String {
    let negative = value < 0;
    let magnitude = value.unsigned_abs();
    // `B` is bin, `M` is milyon: the same suffixes a Turkish reader meets on a
    // counter, so 12.900 reads as "12,9B" rather than as an unfamiliar "12.9K".
    let (whole, tenths, suffix) = if magnitude < 1_000_000 {
        (magnitude / 1_000, (magnitude / 100) % 10, 'B')
    } else {
        (magnitude / 1_000_000, (magnitude / 100_000) % 10, 'M')
    };
    let sign = if negative { "-" } else { "" };
    let rendered = if tenths == 0 {
        format!("{whole}{suffix}")
    } else {
        format!("{whole},{tenths}{suffix}")
    };
    if magnitude < 1_000 {
        value.to_string()
    } else {
        format!("{sign}{rendered}")
    }
}

/// Render the account's avatar, or its initial when no picture was uploaded.
///
/// An account that never chose a picture is drawn as a letter tile rather than
/// an `<img>`: the letter is part of the page, so the header never shows an
/// empty box while an image request is in flight, fails, or returns a pattern
/// the visitor reads as a broken image.
fn render_avatar(account: &User) -> String {
    if account.avatar_file.is_some() {
        return format!(
            r#"<img class="profile-avatar" src="/auth/avatar/{user_id}?v={version}" width="104" height="104" alt="{alt}">"#,
            user_id = account.id,
            version = escape_html(&crate::templates::auth::avatar_version(
                account.avatar_file.as_deref(),
            )),
            alt = escape_html(&account.display_name),
        );
    }
    format!(
        r#"<span class="profile-avatar profile-avatar-letter" role="img" aria-label="{alt}">{initial}</span>"#,
        alt = escape_html(&account.display_name),
        initial = escape_html(&crate::templates::auth::account_initial(
            &account.display_name,
            &account.username,
        )),
    )
}

/// Render the profile header: a cover, the picture that sits over its lower
/// edge, the name, the handle, the description, and three numbers.
///
/// The order is the whole design and it is fixed: cover, picture, name, handle,
/// description, numbers. A reader recognises a person by the picture and the
/// name before anything else, and a name above a picture reads as a heading
/// over a page rather than as a person.
///
/// The cover fades into the page background instead of ending at an edge, so
/// there is no line between the picture and the name; the picture hangs over
/// that fade, which is what ties the two halves together.
///
/// The three numbers are the score the account's posts earned, the total of
/// everything it wrote, and how long it has been here. "Karma" is not one of
/// them: the number is a count of upvotes and is called what it is.
fn render_header(account: &User, stats: &ProfileStats) -> String {
    let bio = if account.bio.trim().is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="profile-bio">{}</p>"#,
            escape_html(account.bio.trim())
        )
    };
    // Everything the account wrote: the threads it opened and the replies it
    // left. `post_count` already counts the opening posts, so adding the
    // replies to it would count them twice.
    let contributions = stats.post_count;
    format!(
        r##"<header class="profile-header">
<div class="profile-cover" aria-hidden="true"></div>
<div class="profile-head">
{avatar}
<div class="profile-identity">
<h1 class="profile-name">{display_name} {badge}</h1>
<p class="profile-handle">@{username}</p>
{bio}
</div>
</div>
<div class="profile-metrics">
<div class="profile-metric">
<span class="profile-metric-value">{score}</span>
<span class="profile-metric-label">Skor</span>
</div>
<div class="profile-metric">
<span class="profile-metric-value">{contributions}</span>
<span class="profile-metric-label">Katkılar</span>
</div>
<div class="profile-metric">
<span class="profile-metric-value profile-metric-value-age">{account_age}</span>
<span class="profile-metric-label">Hesap Yaşı</span>
</div>
</div>
</header>"##,
        avatar = render_avatar(account),
        display_name = escape_html(&account.display_name),
        badge = crate::templates::admin::role_badge_html(account.badge(chrono::Utc::now().timestamp())),
        username = escape_html(&account.username),
        bio = bio,
        account_age = escape_html(&fmt_account_age(account.created_at)),
        score = fmt_compact_count(stats.karma),
        contributions = fmt_compact_count(contributions),
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
        ProfileTab::Posts => "henüz bir paylaşım yapmamış.",
        ProfileTab::Replies => "henüz yorum yazmamış.",
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
        ProfileTab::Posts => {
            for thread in threads {
                feed.push_str(&render_thread_entry(thread, referenced_boards));
            }
        }
        ProfileTab::Replies => {
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

    use super::{fmt_account_age, fmt_compact_count, profile_page, ProfileTab};
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
            role: crate::roles::UserRole::User,
            status: crate::roles::AccountStatus::Active,
            suspended_until: None,
            created_at: 1_700_000_000,
        }
    }

    fn stats() -> ProfileStats {
        ProfileStats {
            thread_count: 1,
            post_count: 2,
            reply_count: 1,
            thread_likes: 1,
            comment_likes: 2,
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
        assert!(html.contains(r#"<span class="profile-metric-value">3</span>"#));
        assert!(html.contains(r#"href="/u/anon?tab=replies""#));
        assert!(html.contains(">Paylaşımlar<"));
        assert!(html.contains(">Yorumlar<"));
        assert!(html.contains(r#"href="/g/thread/4#p5""#));
        assert!(html.contains(r#"href="/g/""#));
        // A reference with no matching post stays plain text instead of
        // becoming a link that leads nowhere.
        assert!(html.contains("&gt;&gt;1 selam"));
    }

    /// Render the page for one account, with everything else held constant.
    fn page_for(subject: &User) -> String {
        profile_page(
            subject,
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
        )
    }

    #[test]
    /// The header shows the badge the account has earned or been given, next to
    /// the name it belongs to, and the state in force outranks both.
    fn profile_header_shows_the_account_badge() {
        let mut trusted = account();
        trusted.karma = 500;
        let html = page_for(&trusted);
        assert!(html.contains("role-badge-god"), "got {html}");
        assert!(html.contains(">God</span>"), "got {html}");

        let mut owner = account();
        owner.role = crate::roles::UserRole::Owner;
        assert!(page_for(&owner).contains("role-badge-owner"));

        let mut banned = account();
        banned.status = crate::roles::AccountStatus::Banned;
        assert!(
            page_for(&banned).contains("role-badge-banned"),
            "a banned account reads as banned, whatever its karma says"
        );
    }

    #[test]
    /// The header links to the uploaded picture by its version. The picture is
    /// cached for a year, so an unversioned URL here is exactly how a fresh
    /// upload never shows up.
    fn profile_header_links_to_the_versioned_picture() {
        let mut with_picture = account();
        with_picture.avatar_file = Some("7-a1b2c3d4e5f6-0.png".to_owned());
        let html = profile_page(
            &with_picture,
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

        assert!(
            html.contains(&format!(
                r#"<img class="profile-avatar" src="/auth/avatar/7?v={}""#,
                crate::templates::auth::avatar_version(with_picture.avatar_file.as_deref())
            )),
            "the header has to ask for the stored version of the picture"
        );
    }

    #[test]
    /// The two tabs list different things: what the account opened, and what it
    /// said in somebody else's thread. An account with neither says so instead
    /// of rendering an empty list.
    fn profile_page_switches_listing_per_tab() {
        let posts_html = profile_page(
            &account(),
            &stats(),
            ProfileTab::Posts,
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
        assert!(posts_html.contains("1 yanıt"));
        assert!(
            !posts_html.contains("&gt;&gt;1 selam"),
            "a reply must not be listed as a post the account opened"
        );

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
        assert!(empty_html.contains("henüz yorum yazmamış."));
    }

    #[test]
    /// The header leads with the score, the contributions, and the account age,
    /// in that order and in one row. "Karma" is not one of them: the number is
    /// a count of upvotes and is called what it is.
    fn profile_header_shows_the_score_the_contributions_and_the_account_age() {
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

        let metrics = html
            .split_once(r#"<div class="profile-metrics">"#)
            .and_then(|(_, rest)| rest.split_once(r#"<section class="profile-feed">"#))
            .map_or("", |(metrics, _)| metrics);
        assert!(
            metrics.contains("Skor") && metrics.contains("Katkılar") && metrics.contains("Hesap Yaşı"),
            "the three numbers should share one row: {metrics}"
        );
        let score = metrics.find("Skor").unwrap_or(0);
        let contributions = metrics.find("Katkılar").unwrap_or(0);
        let age = metrics.find("Hesap Yaşı").unwrap_or(0);
        assert!(
            score < contributions && contributions < age,
            "the score leads, the contributions follow, the age closes: {metrics}"
        );
        assert!(!html.contains("Karma"), "the score is not called karma");
        assert!(!html.contains("Katıldı"), "the old join label should be gone");

        // The score is the account's own upvote total, not a made-up number.
        assert!(
            metrics.contains(&format!(">{}<", stats().karma)),
            "the score shown should be the recorded vote total: {metrics}"
        );
        // The contributions are everything the account wrote: two posts, one of
        // which is its own opening post, plus the reply inside the two.
        assert!(
            metrics.contains(&format!(">{}<", stats().post_count)),
            "the contributions shown should be the post total: {metrics}"
        );

        let expected = fmt_account_age(1_700_000_000);
        assert!(
            metrics.contains(&expected),
            "the account age should be rendered as {expected}"
        );
    }

    #[test]
    /// The header is read cover first, then the picture over its edge, then the
    /// name, the handle, and the description. A name above the picture reads as
    /// a page heading rather than as a person.
    fn profile_header_reads_cover_picture_name_handle_description() {
        let html = profile_html_for_bio("selam");
        let cover = html.find(r#"<div class="profile-cover""#).unwrap_or(0);
        let avatar = html.find(r#"class="profile-avatar"#).unwrap_or(0);
        let name = html.find(r#"<h1 class="profile-name">"#).unwrap_or(0);
        let handle = html.find(r#"<p class="profile-handle">"#).unwrap_or(0);
        let bio = html.find(r#"<p class="profile-bio">"#).unwrap_or(0);
        assert!(
            cover < avatar && avatar < name && name < handle && handle < bio,
            "the header order is fixed: {cover} {avatar} {name} {handle} {bio}"
        );
    }

    #[test]
    /// A count past a thousand is shortened rather than left to push the row
    /// off a phone, and a small one is left exactly as it is.
    fn compact_counts_shorten_only_when_they_have_to() {
        assert_eq!(fmt_compact_count(0), "0");
        assert_eq!(fmt_compact_count(173), "173");
        assert_eq!(fmt_compact_count(999), "999");
        assert_eq!(fmt_compact_count(1_000), "1B");
        assert_eq!(fmt_compact_count(12_900), "12,9B");
        assert_eq!(fmt_compact_count(1_000_000), "1M");
        assert_eq!(fmt_compact_count(2_450_000), "2,4M");
        assert_eq!(fmt_compact_count(-1_500), "-1,5B");
    }

    /// Render the page for an account carrying the given description.
    fn profile_html_for_bio(bio: &str) -> String {
        let mut account = account();
        account.bio = bio.to_owned();
        profile_page(
            &account,
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
        )
    }

    #[test]
    /// A description an account writes in its settings is the line the profile
    /// shows, escaped, in the header next to the names.
    fn profile_shows_the_description_the_account_wrote() {
        let html = profile_html_for_bio("  bosluk & <b>etiket</b>  ");
        assert!(
            html.contains(r#"<p class="profile-bio">bosluk &amp; &lt;b&gt;etiket&lt;/b&gt;</p>"#),
            "the description is trimmed and escaped before it is rendered"
        );
    }

    #[test]
    /// An account with no description leaves the line out rather than filling
    /// the gap with a sentence about itself: the header is a name and a
    /// picture, and an apology is neither.
    fn profile_leaves_out_a_description_it_does_not_have() {
        let html = profile_html_for_bio("   ");
        assert!(
            !html.contains(r#"class="profile-bio""#),
            "no description, no paragraph: {html}"
        );
    }
}
