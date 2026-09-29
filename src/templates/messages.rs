//! Pages for direct messages.
//!
//! These are the only pages on the site that are about one reader rather than
//! about the board, so they carry no board navigation: everything on them
//! belongs to the account that is signed in.

use std::fmt::Write as _;

use crate::db::{ConversationSummary, DirectMessage};
use crate::utils::sanitize::escape_html;

use super::Pagination;

/// Messages shown on one page of a conversation.
const MESSAGES_PER_PAGE: i64 = 50;

/// Query fields accepted by one conversation page.
#[derive(Debug, serde::Deserialize)]
pub struct ConversationQuery {
    /// Which page of the exchange to show.
    pub page: Option<i64>,
}

/// Wrap a message page in the site layout.
fn page(title: &str, body: &str, csrf_token: &str) -> String {
    super::base_layout_with_preferences(
        title,
        None,
        body,
        csrf_token,
        &[],
        None,
        None,
        false,
        "",
        super::UserPreferences::default(),
    )
}

/// Render a timestamp the way the rest of the site does.
fn when(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|time| time.format("%d.%m.%Y %H:%M").to_string())
        .unwrap_or_else(|| "-".to_owned())
}

/// Render the list of conversations.
///
/// A line the other account has closed stays on the list, marked as closed,
/// because a block stops new messages; it does not rewrite a history the
/// reader already has. Hiding it would make messages vanish from under a
/// reader with no way to find out why.
pub fn conversations_page(
    conversations: &[ConversationSummary],
    blocked: &[(i64, String)],
    csrf_token: &str,
) -> String {
    let mut body = String::from(
        r#"<div class="page-box messages-page">
<h2 class="messages-title">Mesajlar</h2>"#,
    );

    if conversations.is_empty() {
        body.push_str(
            r#"<p class="messages-empty">Henüz hiçbir sohbetin yok. Bir kullanıcının profilinden ona mesaj gönderebilirsin.</p>"#,
        );
    } else {
        body.push_str(r#"<ul class="message-list">"#);
        for entry in conversations {
            let unread_note = if entry.unread > 0 {
                format!(r#"<span class="message-unread">{} okunmadı</span>"#, entry.unread)
            } else {
                String::new()
            };
            let closed_note = if entry.blocked_by_other {
                r#"<span class="message-closed">kapalı</span>"#.to_owned()
            } else {
                String::new()
            };
            let _ = write!(
                body,
                r#"<li class="message-list-item{unread_class}">
<a class="message-list-link" href="/messages/{id}">
<span class="message-list-name">{name}</span>
<span class="message-list-preview">{preview}</span>
<span class="message-list-when">{when}</span>
{unread_note}{closed_note}
</a>
</li>"#,
                unread_class = if entry.unread > 0 {
                    " message-list-item-unread"
                } else {
                    ""
                },
                id = entry.id,
                name = escape_html(&entry.other_display_name),
                preview = escape_html(&entry.last_body),
                when = escape_html(&when(entry.last_at)),
            );
        }
        body.push_str("</ul>");
    }

    body.push_str(r#"<h3 class="messages-subtitle">Engellenen hesaplar</h3>"#);
    if blocked.is_empty() {
        body.push_str(r#"<p class="messages-empty">Kimseyi engellemedin.</p>"#);
    } else {
        body.push_str(r#"<ul class="message-block-list">"#);
        for (user_id, username) in blocked {
            let _ = write!(
                body,
                r#"<li class="message-block-item">
<span class="message-block-name">@{name}</span>
<form method="POST" action="/messages/block" class="message-block-form">
  <input type="hidden" name="user_id" value="{id}">
  <input type="hidden" name="blocked" value="0">
  <input type="hidden" name="return_to" value="/messages">
  <input type="hidden" name="_csrf" value="{csrf}">
  <button type="submit">engeli kaldır</button>
</form>
</li>"#,
                name = escape_html(username),
                id = user_id,
                csrf = escape_html(csrf_token),
            );
        }
        body.push_str("</ul>");
    }

    body.push_str("</div>");
    page("Mesajlar", &body, csrf_token)
}

/// Render one conversation.
///
/// The delete control appears only on a message the reader sent. A message
/// somebody else wrote is not theirs to take back, and a button that cannot
/// work is worse than no button at all.
pub fn conversation_page(
    entry: &ConversationSummary,
    messages: &[DirectMessage],
    total: i64,
    reader_id: i64,
    csrf_token: &str,
    page_number: i64,
) -> String {
    let mut body = format!(
        r#"<div class="page-box message-thread" data-conversation-id="{id}">
<h2 class="messages-title">{name}</h2>"#,
        id = entry.id,
        name = escape_html(&entry.other_display_name),
    );

    if entry.blocked_by_other {
        body.push_str(
            r#"<p class="message-closed-note">Bu hesap seni engelledi, yeni mesaj gönderemezsin.</p>"#,
        );
    }

    body.push_str(r#"<div class="message-thread-body">"#);
    for message in messages {
        let mine = message.sender_id == reader_id;
        let delete_control = if mine {
            format!(
                r#"<form method="POST" action="/messages/delete" class="message-delete-form">
  <input type="hidden" name="conversation_id" value="{conversation}">
  <input type="hidden" name="message_id" value="{message}">
  <input type="hidden" name="return_to" value="/messages/{conversation}">
  <input type="hidden" name="_csrf" value="{csrf}">
  <button type="submit" title="Mesajı sil">sil</button>
</form>"#,
                conversation = entry.id,
                message = message.id,
                csrf = escape_html(csrf_token),
            )
        } else {
            String::new()
        };
        let _ = write!(
            body,
            r#"<div class="message-bubble{cls}">
<div class="message-meta">{sender} · {when}</div>
<div class="message-body">{body}</div>
{delete_control}
</div>"#,
            cls = if mine {
                " message-bubble-mine"
            } else {
                " message-bubble-theirs"
            },
            sender = escape_html(&message.sender_username),
            when = escape_html(&when(message.created_at)),
            body = escape_html(&message.body),
        );
    }
    body.push_str("</div>");

    let pagination = Pagination::new(page_number, MESSAGES_PER_PAGE, total);
    if pagination.total_pages() > 1 {
        body.push_str(&super::render_pagination(
            &pagination,
            &format!("/messages/{}", entry.id),
        ));
    }

    let _ = write!(
        body,
        r#"<form method="POST" action="/messages" class="message-compose">
<input type="hidden" name="conversation_id" value="{id}">
<input type="hidden" name="return_to" value="/messages/{id}">
<input type="hidden" name="_csrf" value="{csrf}">
<textarea name="body" rows="3" maxlength="4000" placeholder="mesajını yaz…" required></textarea>
<button type="submit">gönder</button>
</form>
<form method="POST" action="/messages/leave/{id}" class="message-leave-form">
  <input type="hidden" name="return_to" value="/messages">
  <input type="hidden" name="_csrf" value="{csrf}">
  <button type="submit">sohbeti kapat</button>
</form>
</div>"#,
        id = entry.id,
        csrf = escape_html(csrf_token),
    );

    page(
        &format!("{} — Mesajlar", entry.other_display_name),
        &body,
        csrf_token,
    )
}
