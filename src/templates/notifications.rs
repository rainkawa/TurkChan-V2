//! The notification centre.
//!
//! A notification is only worth having if pressing it goes where the thing
//! happened, so the link is built from what was recorded: a direct message
//! opens the line, a reply opens the post, and anything whose target has since
//! been deleted falls back to the board it came from rather than to a page
//! that no longer exists.

use std::fmt::Write as _;

use crate::db::{Notification, NotificationKind};
use crate::utils::sanitize::escape_html;

use super::Pagination;

/// Notifications shown on one page.
const NOTIFICATIONS_PER_PAGE: i64 = 25;

/// Query fields accepted by the notification centre.
#[derive(Debug, serde::Deserialize)]
pub struct NotificationsQuery {
    /// Which page of the list to show.
    pub page: Option<i64>,
}

/// Render a timestamp the way the rest of the site does.
fn when(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|time| time.format("%d.%m.%Y %H:%M").to_string())
        .unwrap_or_else(|| "-".to_owned())
}

/// The word a notification kind is shown as.
fn kind_label(kind: NotificationKind) -> &'static str {
    match kind {
        NotificationKind::Reply => "yanıt",
        NotificationKind::Mention => "bahsedilme",
        NotificationKind::Upvote => "oy",
        NotificationKind::Downvote => "eksi oy",
        NotificationKind::DirectMessage => "mesaj",
        NotificationKind::Moderation => "moderasyon",
        NotificationKind::System => "sistem",
    }
}

/// Where a notification takes the reader when it is pressed.
fn link_for(item: &Notification) -> String {
    if item.kind == NotificationKind::DirectMessage {
        return "/messages".to_owned();
    }
    match (item.board_short.as_deref(), item.thread_id) {
        (Some(board), Some(thread)) => match item.post_id {
            Some(post) => format!("/{board}/thread/{thread}#p{post}"),
            None => format!("/{board}/thread/{thread}"),
        },
        (Some(board), None) => format!("/{board}"),
        (None, _) => "/".to_owned(),
    }
}

/// Render the notification centre.
///
/// Read and unread are marked in the markup itself and not only in colour, so
/// the state survives a reader who cannot see the colour, and so the live
/// badge and this list can be compared by a test.
pub fn notifications_page(
    notifications: &[Notification],
    unread: i64,
    total: i64,
    csrf_token: &str,
    page_number: i64,
) -> String {
    let mut body = format!(
        r#"<div class="page-box notifications-page">
<h2 class="messages-title">Bildirimler</h2>
<p class="notifications-summary">{unread} okunmamış / {total} toplam</p>"#,
        unread = unread,
        total = total,
    );

    if unread > 0 {
        let _ = write!(
            body,
            r#"<form method="POST" action="/notifications/read" class="notifications-read-all">
  <input type="hidden" name="all" value="1">
  <input type="hidden" name="return_to" value="/notifications">
  <input type="hidden" name="_csrf" value="{csrf}">
  <button type="submit">Tümünü okundu yap</button>
</form>"#,
            csrf = escape_html(csrf_token),
        );
    }

    if notifications.is_empty() {
        body.push_str(r#"<p class="messages-empty">Bildirimin yok.</p>"#);
    } else {
        body.push_str(r#"<ul class="notification-list">"#);
        for item in notifications {
            let _ = write!(
                body,
                r#"<li class="notification-item{cls}" data-notification-id="{id}">
<a class="notification-link" href="{href}">
<span class="notification-kind">{kind}</span>
<span class="notification-summary">{summary}</span>
<span class="notification-when">{when}</span>
</a>
</li>"#,
                cls = if item.is_read {
                    " notification-item-read"
                } else {
                    " notification-item-unread"
                },
                id = item.id,
                href = escape_html(&link_for(item)),
                kind = escape_html(kind_label(item.kind)),
                summary = escape_html(&item.summary),
                when = escape_html(&when(item.created_at)),
            );
        }
        body.push_str("</ul>");
    }

    let pagination = Pagination::new(page_number, NOTIFICATIONS_PER_PAGE, total);
    if pagination.total_pages() > 1 {
        body.push_str(&super::render_pagination(
            &pagination,
            "/notifications",
        ));
    }
    body.push_str("</div>");

    super::base_layout_with_preferences(
        "Bildirimler",
        None,
        &body,
        csrf_token,
        &[],
        None,
        None,
        false,
        "",
        super::UserPreferences::default(),
    )
}
