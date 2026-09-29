//! Direct messages and notifications, as pages and actions.
//!
//! A message is written by a form and read back by a redirect, the same way a
//! vote is: the reader presses a button while looking at something and lands
//! back where they were, so the thread they were in does not disappear from
//! under them mid-conversation.
//!
//! Signing in is required here and is checked rather than assumed, because
//! every route in this file exposes somebody's private words.

use crate::db;
use crate::error::{AppError, Result};
use crate::middleware::{AppState, SecureCookieContext};
use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse as _, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::templates::messages as message_templates;
use crate::templates::notifications as notification_templates;
use crate::utils::redirect::strict_safe_internal_path_or;

/// Messages shown on one page of a conversation.
const MESSAGES_PER_PAGE: i64 = 50;

/// Notifications delivered in one stream event.
const STREAM_BATCH: i64 = 25;

/// Notifications shown on one page of the centre.
const NOTIFICATIONS_PER_PAGE: i64 = 25;

/// Form fields submitted by the message box.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct SendMessageForm {
    /// The conversation being written to.
    conversation_id: i64,
    /// The message text.
    body: String,
    /// Where the press happened, so the reader lands back in the thread.
    return_to: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Form fields submitted by the block control.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct BlockForm {
    /// The account being blocked or unblocked.
    user_id: i64,
    /// `1` to block, `0` to unblock.
    blocked: i64,
    /// Where the press happened.
    return_to: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Form fields submitted by the delete control on one message.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct DeleteMessageForm {
    /// The conversation the message was in.
    conversation_id: i64,
    /// The message being deleted.
    message_id: i64,
    /// Where the press happened.
    return_to: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Form fields submitted by the leave control.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct LeaveConversationForm {
    /// Where the press happened.
    return_to: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Turn a refusal into the words the reader is shown.
///
/// A block and a missing account are told apart on purpose: one is something
/// the reader did and can undo, the other is a link that no longer works, and
/// saying the wrong one sends somebody looking for a control that is not there.
fn refusal_message(error: db::DirectMessageError) -> AppError {
    let Some(refusal) = error.refusal() else {
        // A storage failure is the operator's to hear about, not something to
        // dress up as a block: telling a reader they are blocked when the
        // database was unreachable would be a lie they could not argue with.
        return AppError::Internal(anyhow::anyhow!("{error}"));
    };
    match refusal {
        db::DirectMessageRefusal::Blocked => {
            AppError::Forbidden("Bu hesapla mesajlaşmak engellenmiş.".into())
        }
        db::DirectMessageRefusal::NoSuchAccount => {
            AppError::NotFound("Hesap bulunamadı.".into())
        }
        db::DirectMessageRefusal::Body => {
            AppError::BadRequest("Mesaj boş olamaz ve çok uzun olamaz.".into())
        }
    }
}

/// Return the account id a request is signed in as, or refuse.
///
/// `None` is refused in words rather than answered with an empty page: an empty
/// message list and a message list that is not yours look the same on the
/// page, and only one of them is an answer.
fn required_account(state: &AppState, jar: &CookieJar) -> Result<i64> {
    crate::handlers::auth::current_account_id(state, jar)?
        .ok_or_else(|| AppError::Forbidden("Bu sayfayı görmek için giriş yapmalısın.".into()))
}

/// GET /messages — the list of conversations.
pub(in crate::server) async fn conversations_page(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response> {
    let account_id = required_account(&state, &jar)?;
    let (jar, csrf) = crate::handlers::board::ensure_csrf_for_request(
        jar,
        &headers,
        SecureCookieContext::default(),
    );

    let html = tokio::task::spawn_blocking({
        let pool = state.db.clone();
        move || -> Result<String> {
            let conn = pool.get()?;
            let conversations = db::list_conversations(&conn, account_id)?;
            let blocked = db::list_blocked(&conn, account_id)?;
            Ok(message_templates::conversations_page(
                &conversations,
                &blocked,
                &csrf,
            ))
        }
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Conversations page task failed: {error}")))??;

    Ok((jar, Html(html)).into_response())
}

/// GET /messages/{id} — one conversation.
pub(in crate::server) async fn conversation_page(
    State(state): State<AppState>,
    Path(conversation_id): Path<i64>,
    Query(q): Query<message_templates::ConversationQuery>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response> {
    let account_id = required_account(&state, &jar)?;
    let (jar, csrf) = crate::handlers::board::ensure_csrf_for_request(
        jar,
        &headers,
        SecureCookieContext::default(),
    );
    let page = q.page.unwrap_or(1).max(1);

    let html = tokio::task::spawn_blocking({
        let pool = state.db.clone();
        move || -> Result<String> {
            let conn = pool.get()?;
            if !db::conversation_includes_member(&conn, conversation_id, account_id)? {
                return Err(AppError::NotFound("Sohbet bulunamadı.".into()));
            }
            // Opening a thread is what marks it read, so the count in the
            // header and the badge in the list agree with what is on screen.
            let mut messages = db::conversation_messages(
                &conn,
                conversation_id,
                account_id,
                MESSAGES_PER_PAGE,
            )?;
            let total = i64::try_from(messages.len()).unwrap_or(i64::MAX);
            let first = ((page - 1) * MESSAGES_PER_PAGE).max(0);
            if first > 0 {
                if usize::try_from(first).unwrap_or(usize::MAX) >= messages.len() {
                    return Err(AppError::NotFound("Sayfa bulunamadı.".into()));
                }
                messages.drain(..usize::try_from(first).unwrap_or(usize::MAX));
            }
            db::mark_conversation_read(&conn, conversation_id, account_id)?;
            let conversations = db::list_conversations(&conn, account_id)?;
            let other = conversations
                .iter()
                .find(|entry| entry.id == conversation_id)
                .ok_or_else(|| AppError::NotFound("Sohbet bulunamadı.".into()))?;
            Ok(message_templates::conversation_page(
                other,
                &messages,
                total,
                account_id,
                &csrf,
                page,
            ))
        }
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Conversation page task failed: {error}")))??;

    Ok((jar, Html(html)).into_response())
}

/// POST /messages — write one message.
pub(in crate::server) async fn send_message(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<SendMessageForm>,
) -> Result<Response> {
    crate::handlers::board::check_csrf_jar(&jar, form.csrf.as_deref())?;
    let back = strict_safe_internal_path_or(
        form.return_to.as_deref(),
        &format!("/messages/{}", form.conversation_id),
    )
    .to_owned();
    let account_id = required_account(&state, &jar)?;

    let pool = state.db.clone();
    let conversation_id = form.conversation_id;
    let body = form.body;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        let message_id = db::send_message(&conn, conversation_id, account_id, &body)
            .map_err(refusal_message)?;
        // The recipient is told here, at the moment the message exists, rather
        // than by a sweep that might not run for another window.
        if let Some(recipient_id) = db::other_conversation_member(&conn, conversation_id, account_id)? {
            let sender = db::find_user_by_id(&conn, account_id)?
                .map_or_else(|| "Bir kullanıcı".to_owned(), |user| user.username);
            db::notify_direct_message(
                &conn,
                recipient_id,
                account_id,
                message_id,
                format!("{sender} sana mesaj gönderdi"),
            )?;
        }
        Ok(())
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Send message task failed: {error}")))??;

    Ok(Redirect::to(&back).into_response())
}

/// POST /messages/delete — take back one message.
pub(in crate::server) async fn delete_message(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<DeleteMessageForm>,
) -> Result<Response> {
    crate::handlers::board::check_csrf_jar(&jar, form.csrf.as_deref())?;
    let back = strict_safe_internal_path_or(
        form.return_to.as_deref(),
        &format!("/messages/{}", form.conversation_id),
    )
    .to_owned();
    let account_id = required_account(&state, &jar)?;

    let pool = state.db.clone();
    let message_id = form.message_id;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        // A message that is not the caller's is left exactly as it was, and
        // the reader is told so rather than shown a silent no-op.
        if !db::delete_message(&conn, message_id, account_id)? {
            return Err(AppError::Forbidden(
                "Bu mesajı yalnızca gönderen silebilir.".into(),
            ));
        }
        Ok(())
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Delete message task failed: {error}")))??;

    Ok(Redirect::to(&back).into_response())
}

/// POST /messages/leave — close the line, keeping your own copy.
pub(in crate::server) async fn leave_conversation(
    State(state): State<AppState>,
    Path(conversation_id): Path<i64>,
    jar: CookieJar,
    Form(form): Form<LeaveConversationForm>,
) -> Result<Response> {
    crate::handlers::board::check_csrf_jar(&jar, form.csrf.as_deref())?;
    let back = strict_safe_internal_path_or(form.return_to.as_deref(), "/messages").to_owned();
    let account_id = required_account(&state, &jar)?;

    let pool = state.db.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        db::leave_conversation(&conn, conversation_id, account_id)
            .map_err(|error| AppError::Internal(anyhow::anyhow!("{error}")))
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Leave conversation task failed: {error}")))??;

    Ok(Redirect::to(&back).into_response())
}

/// POST /messages/block — block or unblock an account.
pub(in crate::server) async fn set_block(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<BlockForm>,
) -> Result<Response> {
    crate::handlers::board::check_csrf_jar(&jar, form.csrf.as_deref())?;
    let back = strict_safe_internal_path_or(form.return_to.as_deref(), "/messages").to_owned();
    let account_id = required_account(&state, &jar)?;

    let pool = state.db.clone();
    let target = form.user_id;
    let blocked = form.blocked != 0;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        db::set_block(&conn, account_id, target, blocked)
            .map_err(|error| AppError::BadRequest(format!("{error}")))
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Block task failed: {error}")))??;

    Ok(Redirect::to(&back).into_response())
}

/// GET /notifications — the notification centre.
pub(in crate::server) async fn notifications_page(
    State(state): State<AppState>,
    Query(q): Query<notification_templates::NotificationsQuery>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response> {
    let account_id = required_account(&state, &jar)?;
    let (jar, csrf) = crate::handlers::board::ensure_csrf_for_request(
        jar,
        &headers,
        SecureCookieContext::default(),
    );
    let page = q.page.unwrap_or(1).max(1);

    let html = tokio::task::spawn_blocking({
        let pool = state.db.clone();
        move || -> Result<String> {
            let conn = pool.get()?;
            let total = db::count_notifications(&conn, account_id)?;
            let listed = db::list_notifications(
                &conn,
                account_id,
                NOTIFICATIONS_PER_PAGE,
                (page - 1) * NOTIFICATIONS_PER_PAGE,
            )?;
            let unread = db::unread_notification_count(&conn, account_id)?;
            Ok(notification_templates::notifications_page(
                &listed,
                unread,
                total,
                &csrf,
                page,
            ))
        }
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Notifications page task failed: {error}")))??;

    Ok((jar, Html(html)).into_response())
}

/// POST /notifications/read — mark one, or all of them, as read.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct MarkReadForm {
    /// The notification being marked, or absent to mark the whole list.
    notification_id: Option<i64>,
    /// `1` to mark every unread notification, `0` to mark just the one.
    all: Option<i64>,
    /// Where the press happened.
    return_to: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

pub(in crate::server) async fn mark_read(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<MarkReadForm>,
) -> Result<Response> {
    crate::handlers::board::check_csrf_jar(&jar, form.csrf.as_deref())?;
    let back = strict_safe_internal_path_or(form.return_to.as_deref(), "/notifications").to_owned();
    let account_id = required_account(&state, &jar)?;

    let pool = state.db.clone();
    let notification_id = form.notification_id;
    let all = form.all.unwrap_or(0) != 0;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        if all || notification_id.is_none() {
            db::mark_all_notifications_read(&conn, account_id)?;
        } else if let Some(id) = notification_id {
            db::mark_notification_read(&conn, id, account_id)?;
        }
        Ok(())
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Mark read task failed: {error}")))??;

    Ok(Redirect::to(&back).into_response())
}

/// GET /notifications/unread — the count the header badge polls for.
///
/// A plain number rather than a page, because the only caller is a badge: a
/// page would mean fetching the whole header to learn one digit. A reader with
/// no session gets zero rather than an error, since the badge is simply not
/// shown and a request that cannot be answered is not worth failing.
pub(in crate::server) async fn unread_count(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response> {
    let Some(account_id) = crate::handlers::auth::current_account_id(&state, &jar)? else {
        return Ok(([("content-type", "text/plain")], "0").into_response());
    };
    let pool = state.db.clone();
    let count = tokio::task::spawn_blocking(move || -> Result<i64> {
        let conn = pool.get()?;
        Ok(db::unread_notification_count(&conn, account_id)?
            + db::unread_message_count(&conn, account_id)?)
    })
    .await
    .map_err(|error| AppError::Internal(anyhow::anyhow!("Unread count task failed: {error}")))??;

    Ok(([("content-type", "text/plain")], count.to_string()).into_response())
}

/// GET /notifications/stream — the live connection a signed-in reader keeps
/// open.
///
/// This is a poll over the stored rows rather than a fan-out from the writer.
/// That choice costs a query every few seconds per open connection and buys
/// the thing a reader actually needs: a notification written by another
/// process, or before this connection was open, arrives exactly like one
/// written while it was watching. A push hub would drop anything a restarted
/// process wrote while nobody was connected to it.
///
/// The connection is refused for a reader with no account rather than left open
/// with nothing to send, and the loop ends on cancellation so a closed browser
/// does not leave a task behind.
pub(in crate::server) async fn notification_stream(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response> {
    let Some(account_id) = crate::handlers::auth::current_account_id(&state, &jar)? else {
        return Err(AppError::Forbidden(
            "Canlı bildirimler için giriş yapmalısın.".into(),
        ));
    };

    let stream = notification_events(state.db.clone(), account_id);

    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(30)))
        .into_response())
}

/// Build the event stream one signed-in reader keeps open.
///
/// Polling the stored rows is the whole design. It costs a query every few
/// seconds per open connection and buys the thing a reader actually needs: a
/// notification written by another process, or before this connection opened,
/// arrives exactly like one written while it was watching. A hub that only
/// forwards what passes through it in this process would drop anything a
/// restarted process wrote while nobody was connected to it.
fn notification_events(
    pool: db::DbPool,
    account_id: i64,
) -> impl futures::Stream<Item = std::result::Result<SseEvent, std::convert::Infallible>> {
    futures::stream::unfold(
        (pool, account_id, StreamCursor::opening()),
        |(pool, account_id, mut cursor)| async move {
            // A poll that found nothing new answers with a keep-alive comment
            // rather than silence, so a proxy in the middle does not close a
            // connection that is simply quiet. The row reader already makes
            // that choice and reports the unread count alongside the rows.
            let event = read_new_notifications(&pool, account_id, &mut cursor).await;
            tokio::time::sleep(STREAM_POLL_INTERVAL).await;
            Some((Ok(event), (pool, account_id, cursor)))
        },
    )
}

/// How long a stream waits before looking again.
const STREAM_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// What a stream has already shown.
///
/// A stream begins having shown nothing at all rather than at the newest row.
/// A reader who opens the page has not read the notifications that are already
/// waiting, so starting past them would leave them sitting unread behind a live
/// connection that looked like it was keeping up.
struct StreamCursor {
    /// The newest row id already sent.
    last_sent: i64,
}

impl StreamCursor {
    /// A cursor that has shown nothing yet.
    const fn opening() -> Self {
        Self { last_sent: 0 }
    }
}

/// Read the reader's total unread count, messages and notifications together.
async fn read_unread_total(pool: &db::DbPool, account_id: i64) -> i64 {
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || -> i64 {
        let Ok(conn) = pool.get() else {
            return 0;
        };
        // The pair is bound to a local rather than written in the scrutinee. A
        // temporary in this tail expression would be dropped before `conn`
        // under the Rust 2024 tail-expression rules this workspace denies,
        // handing the connection back while the errors it produced are still
        // alive.
        let counts = (
            db::unread_notification_count(&conn, account_id),
            db::unread_message_count(&conn, account_id),
        );
        match counts {
            (Ok(notifications), Ok(messages)) => notifications.saturating_add(messages),
            _ => 0,
        }
    })
    .await
    .unwrap_or(0)
}

/// Read what has appeared since the last event and advance the cursor.
async fn read_new_notifications(
    pool: &db::DbPool,
    account_id: i64,
    cursor: &mut StreamCursor,
) -> SseEvent {
    let after = cursor.last_sent;
    // The pool is cloned into the blocking closure under a name of its own rather
    // than shadowing the argument. The unread count read below still needs the
    // pool this function was handed, and a shadow would have moved it.
    let rows = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Vec<db::Notification> {
            let Ok(conn) = pool.get() else {
                return Vec::new();
            };
            db::notifications_since(&conn, account_id, after, STREAM_BATCH).unwrap_or_default()
        }
    })
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        return SseEvent::default().comment("keep-alive");
    }
    for row in &rows {
        cursor.last_sent = cursor.last_sent.max(row.id);
    }
    let unread = read_unread_total(pool, account_id).await;
    SseEvent::default()
        .event("unread")
        .data(unread.to_string())
}
