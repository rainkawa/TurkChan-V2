//! Page templates for thread-level views and individual posts.

use crate::models::{Board, Post, Thread};
use crate::utils::{
    files::format_file_size, redirect::encode_query_component, sanitize::escape_html,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::{
    admin_ban_delete_modal_script, base_layout, base_layout_with_account, compress_modal_script,
    fmt_ts, fmt_ts_short, report_modal_script, thread_autoupdate_script,
};

/// Number of seconds during which a poster may edit or delete a new post.
const SELF_ACTION_WINDOW_SECS: i64 = 60;
/// User-facing explanation of the edit and delete window.
const SELF_ACTION_WINDOW_HINT: &str = "gönderdikten sonra en fazla 60 saniye boyunca kullanılabilir";

/// Time-limited controls available to the author of a post.
#[derive(Debug, Clone)]
pub struct OwnedPostControls {
    /// Unix timestamp at which the controls expire.
    pub expires_at: i64,
}

/// Values used to reopen the edit overlay after a validation error.
#[derive(Debug, Clone)]
pub struct EditOverlayState {
    /// Identifier of the post being edited.
    pub post_id: i64,
    /// Current body text shown in the editor.
    pub body: String,
    /// Optional validation error.
    pub error: Option<String>,
}

/// Renders the live countdown note for edit and delete controls.
fn render_self_action_window_hint(expires_at: i64) -> String {
    format!(
        r#"<span class="self-action-window-note self-delete-countdown" data-role="self-action-countdown" aria-live="polite" data-action-expiry="{expires_at}">{SELF_ACTION_WINDOW_HINT}</span>"#
    )
}

/// Renders a post without self-service or administrative controls.
fn render_post_preview(
    post: &Post,
    board_short: &str,
    csrf_token: &str,
    thread_op_id: Option<i64>,
) -> String {
    render_post(
        post,
        board_short,
        csrf_token,
        RenderPostOpts {
            show_delete: false,
            is_admin: false,
            admin_csrf_token: None,
            show_media: true,
            allow_editing: false,
            allow_self_delete: false,
            owned_post_controls: None,
            vote: None,
            share_by: None,
            author: None,
            show_poster_ids: false,
            collapse_greentext: true,
            thread_state: None,
            thread_op_id,
            video_audio_muted: false,
        },
        SELF_ACTION_WINDOW_SECS,
    )
}

#[must_use]
/// Renders the standalone no-JavaScript edit-post page.
pub fn edit_post_page(
    board: &Board,
    thread: &Thread,
    post: &Post,
    csrf_token: &str,
    boards: &[Board],
    current_theme: Option<&str>,
    error: Option<&str>,
) -> String {
    let mut body = String::new();
    if let Some(msg) = error {
        let _ = write!(
            body,
            r#"<div class="post-error-banner">&#9888; {}</div>"#,
            escape_html(msg)
        );
    }

    let _ = write!(
        body,
        r#"<div class="page-box self-action-page">
<div class="board-thread-header">/{board}/ — No.{pid} gönderisini düzenle</div>
<p class="self-action-page-note">{hint}</p>
<p><a href="/{board}/thread/{tid}#p{pid}">konuya dön</a></p>
<div class="self-action-preview">
{preview}
</div>
<form class="post-form self-action-form" method="POST" action="/{board}/post/{pid}/edit">
  <input type="hidden" name="_csrf" value="{csrf}">
  <table>
    <tr><td>gövde</td>
        <td><textarea name="body" aria-label="gönderi metnini düzenle" rows="8" maxlength="4096" required>{body_text}</textarea></td></tr>
    <tr><td></td>
        <td><button type="submit">düzenlemeyi kaydet</button>
            <a class="edit-btn" href="/{board}/thread/{tid}#p{pid}">vazgeç</a></td></tr>
  </table>
</form>
</div>"#,
        board = escape_html(&board.short_name),
        pid = post.id,
        tid = thread.id,
        hint = SELF_ACTION_WINDOW_HINT,
        preview = render_post_preview(post, &board.short_name, csrf_token, thread.op_id),
        csrf = escape_html(csrf_token),
        body_text = escape_html(&post.body),
    );

    base_layout(
        &format!("/{}/ No.{} gönderisini düzenle", board.short_name, post.id),
        Some(&board.short_name),
        &body,
        csrf_token,
        boards,
        current_theme,
        Some(&board.default_theme),
        board.collapse_greentext,
        &format!("/{}/post/{}/edit", board.short_name, post.id),
    )
}

#[must_use]
/// Renders the standalone no-JavaScript delete-post confirmation page.
pub fn delete_post_page(
    board: &Board,
    thread: &Thread,
    post: &Post,
    csrf_token: &str,
    boards: &[Board],
    current_theme: Option<&str>,
    error: Option<&str>,
) -> String {
    let mut body = String::new();
    if let Some(msg) = error {
        let _ = write!(
            body,
            r#"<div class="post-error-banner">&#9888; {}</div>"#,
            escape_html(msg)
        );
    }

    let _ = write!(
        body,
        r#"<div class="page-box self-action-page">
<div class="board-thread-header">/{board}/ — No.{pid} gönderisini sil</div>
<p class="self-action-page-note">{hint}</p>
<p><a href="/{board}/thread/{tid}#p{pid}">konuya dön</a></p>
<div class="self-action-preview">
{preview}
</div>
<form class="post-form self-action-form" method="POST" action="/{board}/post/{pid}/delete">
  <input type="hidden" name="_csrf" value="{csrf}">
  <p class="self-action-confirm">bu gönderi kalıcı olarak silinsin mi?</p>
  <button type="submit" class="del-btn">gönderiyi sil</button>
  <a class="edit-btn" href="/{board}/thread/{tid}#p{pid}">vazgeç</a>
</form>
</div>"#,
        board = escape_html(&board.short_name),
        pid = post.id,
        tid = thread.id,
        hint = SELF_ACTION_WINDOW_HINT,
        preview = render_post_preview(post, &board.short_name, csrf_token, thread.op_id),
        csrf = escape_html(csrf_token),
    );

    base_layout(
        &format!("/{}/ No.{} gönderisini sil", board.short_name, post.id),
        Some(&board.short_name),
        &body,
        csrf_token,
        boards,
        current_theme,
        Some(&board.default_theme),
        board.collapse_greentext,
        &format!("/{}/post/{}/delete", board.short_name, post.id),
    )
}

/// Renders the top or bottom thread navigation controls.
fn render_thread_nav(board: &Board, thread: &Thread, is_bottom: bool) -> String {
    let jump_link = if is_bottom { "#top" } else { "#bottom" };
    let jump_label = if is_bottom { "Başa" } else { "Sona" };
    let nav_class = if is_bottom {
        "board-header thread-nav thread-nav-bottom"
    } else {
        "board-header thread-nav"
    };
    format!(
        r#"<div class="{nav_class}">
  <div class="thread-nav-group thread-nav-links">
    <a href="/{board_short}">[ Geri ]</a>
    <a href="/{board_short}/catalog">[ Katalog ]</a>
    <a href="{jump_link}">[ {jump_label} ]</a>
  </div>
  <div class="thread-nav-group thread-nav-refresh">
    <noscript><a href="/{board_short}/thread/{thread_id}">[ Şimdi Güncelle ]</a></noscript>
    <button class="thread-nav-btn" type="button" data-action="fetch-updates" data-busy-label="[ Güncelleniyor… ]">[ Şimdi Güncelle ]</button>
    <label class="autoupdate-label">
      <input type="checkbox" data-role="autoupdate-toggle" data-action="autoupdate-toggle">
      <span>Otomatik yenileme</span>
    </label>
  </div>
  <div class="thread-nav-group thread-nav-state">
    <span class="autoupdate-status" data-role="autoupdate-status" role="status" aria-live="polite"></span>
    <span class="thread-reply-stat" title="Yanıt sayısı"><span class="thread-reply-stat-label">Yanıtlar</span>: <span data-role="thread-reply-count">{reply_count}</span></span>
  </div>
</div>
"#,
        nav_class = nav_class,
        board_short = escape_html(&board.short_name),
        jump_link = jump_link,
        jump_label = jump_label,
        reply_count = thread.reply_count,
        thread_id = thread.id,
    )
}

#[must_use]
/// Renders sticky, locked, and archived state badges.
pub fn render_thread_state_badges_full(sticky: bool, locked: bool, archived: bool) -> String {
    let mut badges = String::new();

    if sticky {
        badges.push_str(
            r#"<span class="thread-state-badge thread-state-badge-pin" title="Sabitlendi" aria-label="Sabitlendi">&#128204;</span>"#,
        );
    }

    if archived {
        badges.push_str(
            r#"<span class="thread-state-badge thread-state-badge-archive" title="Arşivlendi" aria-label="Arşivlendi">&#128190;</span>"#,
        );
    } else if locked {
        badges.push_str(
            r#"<span class="thread-state-badge thread-state-badge-lock" title="Kilitli" aria-label="Kilitli">&#128274;</span>"#,
        );
    }

    if badges.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="thread-state-badges">{badges}</span>"#)
    }
}

#[must_use]
/// Renders sticky and locked state badges for a live thread.
pub fn render_thread_state_badges(sticky: bool, locked: bool) -> String {
    render_thread_state_badges_full(sticky, locked, false)
}

#[must_use]
/// Renders the archived state badge and an optional sticky badge.
pub fn render_archive_state_badges(sticky: bool) -> String {
    let mut badges = String::new();

    if sticky {
        badges.push_str(
            r#"<span class="thread-state-badge thread-state-badge-pin" title="Sabitlendi" aria-label="Sabitlendi">&#128204;</span>"#,
        );
    }

    badges.push_str(
        r#"<span class="thread-state-badge thread-state-badge-archive" title="Arşivlendi" aria-label="Arşivlendi">&#128190;</span>"#,
    );

    format!(r#"<span class="thread-state-badges">{badges}</span>"#)
}

// Thread page
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "the thread document keeps navigation, posts, poll, forms, and modals together"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "thread rendering consumes distinct moderation, poll, form, theme, and visitor contexts"
)]
/// Renders a complete thread page.
pub fn thread_page(
    board: &Board,
    thread: &Thread,
    posts: &[Post],
    owned_post_controls: &BTreeMap<i64, OwnedPostControls>,
    post_votes: &BTreeMap<i64, crate::db::PostVoteView>,
    share_authors: &BTreeMap<i64, String>,
    // `author_profiles` carries the account behind each post, read for the
    // identity line in that post's header.
    author_profiles: &BTreeMap<i64, crate::db::PostAuthorProfile>,
    csrf_token: &str,
    boards: &[Board],
    is_admin: bool,
    admin_csrf_token: Option<&str>,
    poll: Option<&crate::models::PollData>,
    error: Option<&str>,
    success: Option<&str>,
    reply_prefill: Option<&super::forms::PostFormState>,
    edit_overlay_state: Option<&EditOverlayState>,
    current_theme: Option<&str>,
    collapse_greentext: bool,
    can_post: bool,
    user_preferences: crate::templates::UserPreferences,
    account: Option<&crate::templates::auth::AccountMenu>,
    account_menu_csrf: &str,
) -> String {
    let mut body = String::new();
    let admin_form_csrf = admin_csrf_token.unwrap_or(csrf_token);
    // A share is named after the account behind the post, not after the reader,
    // and voting needs the reader to have an account of their own. With no
    // account there is nothing to press, so the scores are not even read for
    // this page.
    let no_votes = BTreeMap::new();
    let votes = if account.is_some() {
        post_votes
    } else {
        &no_votes
    };
    let admin_toolbar = if is_admin {
        let sticky_action = if thread.sticky {
            ("unsticky", "&#128204; Sabitlemeyi Kaldır")
        } else {
            ("sticky", "&#128204; Sabitle")
        };
        let lock_action = if thread.locked {
            ("unlock", "&#128275; Kilidi Aç")
        } else {
            ("lock", "&#128274; Kilitle")
        };
        format!(
            r#"<div class="admin-toolbar">
<span class="admin-toolbar-label">&#9632; YÖNETİCİ</span>
<form method="POST" action="/admin/thread/action" style="display:inline">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="thread_id" value="{tid}">
<input type="hidden" name="action" value="{sticky_act}">
<input type="hidden" name="board" value="{board}">
<button type="submit" class="admin-toolbar-btn">{sticky_lbl}</button>
</form>
<form method="POST" action="/admin/thread/action" style="display:inline">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="thread_id" value="{tid}">
<input type="hidden" name="action" value="{lock_act}">
<input type="hidden" name="board" value="{board}">
<button type="submit" class="admin-toolbar-btn">{lock_lbl}</button>
</form>
{archive_btn}
<form method="POST" action="/admin/thread/delete" style="display:inline">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="thread_id" value="{tid}">
<input type="hidden" name="board" value="{board}">
<button type="submit" class="admin-toolbar-btn admin-toolbar-danger"
        data-confirm="Bu konu ve tüm gönderileri silinsin mi?">&#x2715; konuyu sil</button>
</form>
<form method="POST" action="/admin/logout" style="display:inline">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="return_to" value="/{board}/thread/{tid}">
<button type="submit" class="admin-toolbar-btn">çıkış yap</button>
</form>
</div>"#,
            csrf = escape_html(admin_form_csrf),
            tid = thread.id,
            board = escape_html(&board.short_name),
            sticky_act = sticky_action.0,
            sticky_lbl = sticky_action.1,
            lock_act = lock_action.0,
            lock_lbl = lock_action.1,
            archive_btn = if thread.archived {
                String::new()
            } else {
                format!(
                    r#"<form method="POST" action="/admin/thread/action" style="display:inline">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="thread_id" value="{tid}">
<input type="hidden" name="action" value="archive">
<input type="hidden" name="board" value="{board}">
<button type="submit" class="admin-toolbar-btn"
        data-confirm="Bu konu arşivlensin mi? Kilitlenecek ve board arşivine taşınacak.">
  &#128451; Konuyu Arşivle
</button>
</form>"#,
                    csrf = escape_html(admin_form_csrf),
                    tid = thread.id,
                    board = escape_html(&board.short_name),
                )
            }
        )
    } else {
        String::new()
    };

    if let Some(msg) = success {
        let _ = write!(
            body,
            r#"<div class="post-success-banner">{}</div>"#,
            escape_html(msg)
        );
    }

    if let Some(msg) = error {
        let _ = write!(
            body,
            r#"<div class="post-error-banner">&#9888; {}</div>"#,
            escape_html(msg)
        );
    }

    let thread_notice = if thread.archived {
        r#"<div class="notice locked-notice">Bu konu arşivlendi. - Artık yanıt veremezsin.</div>"#
    } else if thread.locked {
        r#"<div class="notice locked-notice">bu konu kilitli — yeni yanıtlara izin verilmiyor</div>"#
    } else {
        ""
    };

    let _ = write!(
        body,
        r#"<div id="top"></div>
<header class="post-header">
<p class="post-header-board"><a href="/{s}">/{s}/</a> &middot; {bn}{access_badge}</p>
<h1 class="post-header-title">{subject}</h1>
<p class="post-header-meta">{posts} yorum &middot; son hareket {bumped}</p>
</header>
{admin_toolbar}
{top_nav}"#,
        s = escape_html(&board.short_name),
        bn = escape_html(&board.name),
        subject = escape_html(
            thread
                .subject
                .as_deref()
                .map(str::trim)
                .filter(|subject| !subject.is_empty())
                .unwrap_or("konu")
        ),
        posts = thread.reply_count,
        bumped = fmt_ts(thread.bumped_at),
        access_badge = super::board::board_access_badge(board),
        admin_toolbar = admin_toolbar,
        top_nav = render_thread_nav(board, thread, false)
    );
    body.push_str(thread_notice);

    if let Some(pd) = poll {
        body.push_str(&render_poll(pd, thread.id, &board.short_name, csrf_token));
    }

    let last_post_id = posts.iter().map(|p| p.id).max().unwrap_or(0);
    let _ = write!(
        body,
        r#"<div id="thread-posts" data-activity-page="thread" data-thread-id="{tid}" data-board="{board}" data-last-id="{last}" data-locked="{locked}" data-sticky="{sticky}" data-archived="{archived}">"#,
        tid = thread.id,
        board = escape_html(&board.short_name),
        last = last_post_id,
        locked = thread.locked,
        sticky = thread.sticky,
        archived = thread.archived,
    );
    for post in posts {
        body.push_str(&render_post(
            post,
            &board.short_name,
            csrf_token,
            RenderPostOpts {
                show_delete: true,
                is_admin,
                admin_csrf_token: admin_csrf_token.map(str::to_owned),
                show_media: true,
                allow_editing: board.allow_editing,
                allow_self_delete: board.allow_self_delete
                    && (!post.is_op || thread.reply_count == 0),
                owned_post_controls: if thread.locked || thread.archived {
                    None
                } else {
                    owned_post_controls.get(&post.id).cloned()
                },
                vote: votes.get(&post.id).copied(),
                share_by: share_authors.get(&post.id).cloned(),
                author: author_profiles.get(&post.id).cloned(),
                show_poster_ids: board.show_poster_ids,
                collapse_greentext: board.collapse_greentext,
                thread_state: Some((thread.sticky, thread.locked, thread.archived)),
                thread_op_id: thread.op_id,
                video_audio_muted: user_preferences.video_audio_muted,
            },
            SELF_ACTION_WINDOW_SECS,
        ));
    }

    body.push_str("</div>\n");
    body.push_str(&render_edit_overlay(
        board,
        thread.id,
        csrf_token,
        edit_overlay_state,
    ));
    if is_admin {
        body.push_str(admin_ban_delete_modal_script());
    }

    if !thread.locked && !thread.archived && can_post {
        let form_html = super::forms::reply_form(
            &board.short_name,
            thread.id,
            csrf_token,
            board,
            reply_prefill,
            account.map_or("", |menu| menu.display_name.as_str()),
        );
        let show_post_form = error.is_some() || reply_prefill.is_some();
        let _ = write!(
            body,
            r##"<div class="post-toggle-bar reply">
  <a class="post-toggle-btn" href="#post-form-wrap" data-action="toggle-post-form">[ Yanıt ]</a>
</div>
<div class="{post_form_class}" id="post-form-wrap" style="{post_form_style}">
  {form_html}
</div>"##,
            post_form_class = if show_post_form {
                "post-form-wrap is-open"
            } else {
                "post-form-wrap is-collapsed"
            },
            post_form_style = if show_post_form {
                "display:block"
            } else {
                "display:none"
            },
        );
    } else if !thread.locked && !thread.archived && board.access_mode.requires_unlock_for_posting()
    {
        body.push_str(&super::board::render_post_access_gate(
            board,
            csrf_token,
            &format!("/{}/thread/{}", board.short_name, thread.id),
            "gönderi kilidini aç",
        ));
    }
    body.push_str("<div id=\"bottom\"></div>\n");
    body.push_str(&render_thread_nav(board, thread, true));

    body.push_str(&compress_modal_script(
        board.max_image_size_bytes(),
        board.max_video_size_bytes(),
    ));
    body.push_str(report_modal_script());
    body.push_str(thread_autoupdate_script());

    // Board-specific values use data attributes because the CSP intentionally
    // forbids inline scripts.

    // Video embed + draft autosave config (data attributes only)
    let embed_enabled_attr = if board.allow_video_embeds { "1" } else { "0" };
    let draft_key = format!("rustchan_draft_{}_{}", board.short_name, thread.id);
    let _ = write!(
        body,
        r#"<div id="thread-config"
     data-embed-enabled="{embed_enabled}"
     data-draft-key="{draft_key}"
     style="display:none" aria-hidden="true"></div>"#,
        embed_enabled = embed_enabled_attr,
        draft_key = escape_html(&draft_key)
    );

    base_layout_with_account(
        &format!(
            "/{}/ - {}",
            board.short_name,
            thread.subject.as_deref().unwrap_or("konu")
        ),
        Some(&board.short_name),
        &body,
        csrf_token,
        boards,
        current_theme,
        Some(&board.default_theme),
        collapse_greentext,
        &format!("/{}/thread/{}", board.short_name, thread.id),
        user_preferences,
        account,
        account_menu_csrf,
    )
}

// Poll renderer
/// Renders a poll voting form or its results.
fn render_poll(
    pd: &crate::models::PollData,
    thread_id: i64,
    board_short: &str,
    csrf_token: &str,
) -> String {
    let now = chrono::Utc::now().timestamp();
    let time_left = pd.poll.expires_at.saturating_sub(now);
    let expires_str = if pd.is_expired {
        "kapatıldı".to_owned()
    } else if time_left < 3600 {
        format!("{} dk sonra kapanıyor", time_left / 60)
    } else if time_left < 86400 {
        format!(
            "{} sa {} dk sonra kapanıyor",
            time_left / 3600,
            (time_left % 3600) / 60
        )
    } else {
        format!("{} tarihinde kapanıyor", fmt_ts(pd.poll.expires_at))
    };

    let show_results = pd.is_expired || pd.user_voted_option.is_some();

    let mut html = format!(
        r#"<div class="poll-container">
<div class="poll-header">
  <span class="poll-icon">📊</span>
  <span class="poll-question">{q}</span>
  <span class="poll-status {status_class}">[{expires}]</span>
</div>"#,
        q = escape_html(&pd.poll.question),
        status_class = if pd.is_expired {
            "poll-closed"
        } else {
            "poll-open"
        },
        // escape_html for defensive correctness — expires_str is
        // derived from integer arithmetic and fmt_ts today, but this guard
        // ensures any future changes to expires_str can't inject HTML.
        expires = escape_html(&expires_str),
    );

    if show_results {
        let total = pd.total_votes.max(1);
        html.push_str(r#"<div class="poll-results">"#);
        for opt in &pd.options {
            let pct = opt
                .vote_count
                .max(0)
                .saturating_mul(100)
                .saturating_add(total / 2)
                .checked_div(total)
                .unwrap_or(0);
            let is_voted = pd.user_voted_option == Some(opt.id);
            let _ = write!(
                html,
                r#"<div class="poll-option-result{voted}">
  <div class="poll-option-label">
    {check}<span class="poll-opt-text">{text}</span>
    <span class="poll-opt-count">{votes} ({pct}%)</span>
  </div>
  <div class="poll-bar-track"><div class="poll-bar-fill" style="width:{pct}%"></div></div>
</div>"#,
                voted = if is_voted { " user-voted" } else { "" },
                check = if is_voted { "✓ " } else { "" },
                text = escape_html(&opt.text),
                votes = opt.vote_count,
                pct = pct
            );
        }
        let _ = write!(
            html,
            r#"<div class="poll-total">{} toplam oy</div></div>"#,
            pd.total_votes,
        );
    } else {
        let _ = write!(
            html,
            r#"<form class="poll-vote-form" method="POST" action="/vote">
<input type="hidden" name="_csrf"     value="{csrf}">
<input type="hidden" name="thread_id" value="{tid}">
<input type="hidden" name="board"     value="{board}">"#,
            csrf = escape_html(csrf_token),
            tid = thread_id,
            board = escape_html(board_short)
        );
        for opt in &pd.options {
            let _ = write!(
                html,
                r#"<label class="poll-vote-option">
  <input type="radio" name="option_id" value="{id}" required>
  <span class="poll-opt-text">{text}</span>
</label>"#,
                id = opt.id,
                text = escape_html(&opt.text)
            );
        }
        html.push_str(
            r#"<button type="submit" class="poll-vote-btn">[ Oy Ver ]</button></form>"#,
        );
    }

    html.push_str("</div>");
    html
}

// Single post renderer
/// Options that control which controls are rendered for a post.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag independently controls a post-rendering capability"
)]
#[derive(Clone, Debug, Default)]
pub struct RenderPostOpts {
    /// Whether to show the legacy delete control.
    pub show_delete: bool,
    /// Whether administrative controls are available.
    pub is_admin: bool,
    /// CSRF token used by administrative forms.
    pub admin_csrf_token: Option<String>,
    /// Whether attached media should be displayed.
    pub show_media: bool,
    /// Whether the author may edit the post.
    pub allow_editing: bool,
    /// Whether the author may delete the post.
    pub allow_self_delete: bool,
    /// Expiring author controls for this post.
    pub owned_post_controls: Option<OwnedPostControls>,
    /// Whether to derive and display a per-thread poster ID.
    pub show_poster_ids: bool,
    /// Whether greentext blocks start collapsed.
    pub collapse_greentext: bool,
    /// Sticky, locked, and archived state for an opening post.
    pub thread_state: Option<(bool, bool, bool)>,
    /// Opening-post identifier used to annotate replies directed at the author.
    pub thread_op_id: Option<i64>,
    /// Whether video and audio elements start muted.
    pub video_audio_muted: bool,
    /// The post's score and the viewer's own vote, when voting is available.
    pub vote: Option<crate::db::PostVoteView>,
    /// Login name of the account the post belongs to, when it belongs to one.
    ///
    /// A share is attributed to that account rather than to the name in the
    /// form, so a share can only ever be published by the person it names.
    pub share_by: Option<String>,
    /// The account behind the post, for the identity shown in its header.
    ///
    /// Read from the join rather than from the post: the name in a post is free
    /// text, so a role or an avatar taken from it would be a claim the reader
    /// could not check.
    pub author: Option<crate::db::PostAuthorProfile>,
}

/// Render one stored tripcode for display.
///
/// A normal tripcode is a derived code, and it is shown as it always has been.
/// A secure tripcode is not derived from anything, so there is no code to show:
/// it is rendered as a lock with the same prefix, which tells the reader that a
/// password was claimed without telling them — or anybody reading the page —
/// anything about it.
fn render_tripcode(stored: &str) -> String {
    if stored == crate::utils::tripcode::SECURE_MARKER {
        return r#"<span class="tripcode tripcode-secure" title="güvenli tripcode: parola gösterilmez">&#128274;</span>"#
            .to_owned();
    }
    format!(r#"<span class="tripcode">!{}</span>"#, escape_html(stored))
}

/// Render the score and the two press buttons for one post.
///
/// The score is public to every reader; the two presses are drawn only for a
/// reader who has an account, because a vote with nobody behind it cannot be
/// cast, taken back, or counted against anybody.
///
/// Each press carries its own value, and that value is the only thing that
/// tells the server which arrow was pressed. A submit button with no `name`
/// sends no field at all, so the form arrives missing the one value it cannot
/// be answered without and every press is rejected before it is read.
///
/// Pressing the arrow that is already pressed takes the vote back, so the same
/// value has to mean the opposite of what it means the first time. The button
/// therefore sends the press, not the intent: the server reads the vote already
/// cast and decides, rather than the markup pretending to know what the reader
/// meant. A reader with scripting off votes the same way; the page is simply
/// re-rendered rather than updated in place.
fn render_vote_controls(
    vote: &crate::db::PostVoteView,
    post_id: i64,
    csrf: &str,
    return_to: &str,
) -> String {
    let up_active = vote.upvoted();
    let down_active = vote.downvoted();
    format!(
        r#"<form class="post-vote" method="POST" action="/post-vote">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="post_id" value="{post_id}">
<input type="hidden" name="return_to" value="{return_to}">
<button type="submit" name="value" value="1" class="vote-btn vote-up{up_active}" title="Beğen" aria-label="Beğen">&#9650;</button>
<output class="vote-score" title="Beğeni puanı">{score}</output>
<button type="submit" name="value" value="-1" class="vote-btn vote-down{down_active}" title="Beğenme" aria-label="Beğenme">&#9660;</button>
</form>"#,
        csrf = csrf,
        post_id = post_id,
        return_to = escape_html(return_to),
        up_active = if up_active { " is-active" } else { "" },
        down_active = if down_active { " is-active" } else { "" },
        score = vote.score,
    )
}

/// Render the share control for one post, naming the account behind it.
///
/// The permalink is shown as text rather than hidden behind a button: a board
/// is shared by copying a line, and the name beside it is who shared it.
/// `None` means the post belongs to no account — written before accounts
/// existed, posted without signing in, or posted anonymously — and there is
/// no control at all for it: a share is a claim that somebody passed this on,
/// and there is no somebody to name.
///
/// The name is the account's own login name, read from `posts.user_id`, and it
/// links to that profile. It is deliberately not the name typed into the form:
/// that field is free text, so treating it as an identity would let anyone
/// publish a share in another account's name, and the link would then point at
/// somebody else's profile while claiming to be theirs.
///
/// An opening post is what a thread is shared by, so it is stated as a share
/// rather than as a link: the reader is told who passed it on before being
/// handed the address. A reply keeps the same control in one quiet line.
fn render_share_control(share_by: Option<&str>, permalink: &str, is_op: bool) -> String {
    let Some(name) = share_by else {
        return String::new();
    };
    let attribution = format!(
        r#"<a class="post-share-author" href="/u/{username}"><strong>@{name}</strong></a> paylaştı"#,
        username = escape_html(name),
        name = escape_html(name),
    );
    if is_op {
        return format!(
            r#"<div class="post-share post-share-op"><span class="post-share-label">konu paylaşımı</span><span class="post-share-by">{attribution}</span><a class="post-share-link" href="{permalink}">{permalink}</a><button type="button" class="post-share-copy" data-action="copy-share-link" data-share-link="{permalink}" data-default-label="kopyala" title="Bağlantıyı kopyala">kopyala</button></div>"#,
            attribution = attribution,
            permalink = escape_html(permalink),
        );
    }
    format!(
        r#"<div class="post-share"><span class="post-share-by">{attribution}</span> <a class="post-share-link" href="{permalink}">{permalink}</a> <button type="button" class="post-share-copy" data-action="copy-share-link" data-share-link="{permalink}" data-default-label="kopyala" title="Bağlantıyı kopyala">kopyala</button></div>"#,
        attribution = attribution,
        permalink = escape_html(permalink),
    )
}

/// Base64 alphabet used for compact poster identifiers.
const POSTER_ID_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Resolves a six-bit value to the corresponding poster-ID character.
fn poster_id_char(index: u8) -> char {
    POSTER_ID_ALPHABET
        .get(usize::from(index))
        .copied()
        .map_or('A', char::from)
}

/// Encodes six hash bytes as an eight-character poster identifier.
fn encode_poster_id(bytes: [u8; 6]) -> String {
    let mut out = String::with_capacity(8);
    let [b0, b1, b2, b3, b4, b5] = bytes;
    out.push(poster_id_char(b0 >> 2));
    out.push(poster_id_char(((b0 & 0x03) << 4) | (b1 >> 4)));
    out.push(poster_id_char(((b1 & 0x0f) << 2) | (b2 >> 6)));
    out.push(poster_id_char(b2 & 0x3f));
    out.push(poster_id_char(b3 >> 2));
    out.push(poster_id_char(((b3 & 0x03) << 4) | (b4 >> 4)));
    out.push(poster_id_char(((b4 & 0x0f) << 2) | (b5 >> 6)));
    out.push(poster_id_char(b5 & 0x3f));
    out
}

/// Derives a thread-scoped poster identifier when the feature is enabled.
fn render_poster_id(post: &Post, show_poster_ids: bool) -> Option<String> {
    if !show_poster_ids {
        return None;
    }
    let ip_hash = post.ip_hash.as_deref()?;
    let mut hasher = Sha256::new();
    hasher.update(crate::config::CONFIG.cookie_secret.as_bytes());
    hasher.update(b":poster-id:");
    hasher.update(post.thread_id.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(ip_hash.as_bytes());
    let digest = hasher.finalize();
    let mut short = [0u8; 6];
    let head = digest.get(..6)?;
    short.copy_from_slice(head);
    Some(encode_poster_id(short))
}

/// Derives deterministic CSS colors for a poster-ID chip.
fn poster_id_chip_style(poster_id: &str) -> String {
    const POSTER_CHIP_HUES: [u16; 18] = [
        0, 210, 122, 32, 282, 168, 338, 52, 196, 96, 16, 248, 146, 308, 72, 184, 228, 356,
    ];

    let mut hasher = Sha256::new();
    hasher.update(b":poster-id-chip:");
    hasher.update(poster_id.as_bytes());
    let digest = hasher.finalize();
    let hue_index = digest
        .first()
        .map_or(0, |byte| usize::from(*byte) % POSTER_CHIP_HUES.len());
    let hue = POSTER_CHIP_HUES.get(hue_index).copied().unwrap_or(200);
    let accent_lightness = 60 + digest.get(1).map_or(0, |byte| u16::from(*byte) % 8);
    let background_lightness = 19 + digest.get(2).map_or(0, |byte| u16::from(*byte) % 8);
    let shadow_strength = 34 + digest.get(3).map_or(0, |byte| u16::from(*byte) % 18);
    format!(
        concat!(
            "--poster-chip-accent:hsl({} 88% {}% / 0.98);",
            "--poster-chip-bg:hsl({} 64% {}% / 0.97);",
            "--poster-chip-fg:hsl({} 100% 97% / 0.99);",
            "--poster-chip-shadow:color-mix(in srgb, var(--poster-chip-accent) {}%, transparent);"
        ),
        hue, accent_lightness, hue, background_lightness, hue, shadow_strength
    )
}

/// Adds an `(OP)` label to same-thread links targeting the opening post.
fn annotate_op_quotelinks(body_html: &str, thread_op_id: Option<i64>) -> String {
    let Some(op_id) = thread_op_id else {
        return body_html.to_owned();
    };
    let target = format!(
        r##"<a href="#p{op_id}" class="quotelink" data-pid="{op_id}">&gt;&gt;{op_id}</a>"##
    );
    let replacement = format!(
        r##"<a href="#p{op_id}" class="quotelink" data-pid="{op_id}">&gt;&gt;{op_id}<span class="quotelink-op-label">(OP)</span></a>"##
    );
    body_html.replace(&target, &replacement)
}

/// Number of filename stem characters displayed before truncation.
const FILE_NAME_STEM_PREFIX_DISPLAY_CHARS: usize = 20;
/// Longest edge the stylesheet gives a post's own thumbnail, in pixels.
pub(super) const THUMB_BOX_PX: i64 = 150;
/// Longest edge the stylesheet gives a reply's thumbnail, in pixels.
pub(super) const THUMB_REPLY_BOX_PX: i64 = 80;
/// Longest edge an expanded image may take, in pixels.
///
/// Mirrors `max-width`/`max-height` in the stylesheet; only the ratio this
/// implies is used, so the constant only has to describe the shape.
const EXPANDED_IMAGE_BOX_PX: i64 = 640;
/// Marker inserted between a truncated filename stem and its extension.
const FILE_NAME_TRUNCATION_MARKER: &str = "(...)";

/// Renders a media thumbnail with a client-side fallback.
///
/// `dims` carries the `width`/`height` attributes that let the browser reserve
/// the space the thumbnail will take, so the thread does not jump down once
/// the image decodes. It is empty for media whose dimensions were never
/// recorded, which is not an error: the layout is then reserved on arrival
/// rather than in advance, exactly as it was before.
fn render_media_thumb(
    img_class: &str,
    fallback_class: &str,
    src: &str,
    alt: &str,
    loading: &str,
    fallback_text: &str,
    dims: &str,
) -> String {
    format!(
        r#"<img class="{img_class}" src="/boards/{src}" loading="{loading}" decoding="async" alt="{alt}" data-media-thumb="1"{dims}>
<div class="{fallback_class} media-thumb-fallback" hidden>{fallback_text}</div>"#,
        img_class = escape_html(img_class),
        fallback_class = escape_html(fallback_class),
        src = escape_html(src),
        loading = escape_html(loading),
        alt = escape_html(alt),
        fallback_text = escape_html(fallback_text),
        dims = dims,
    )
}

/// Scale a stored image's dimensions to a display box, preserving aspect.
///
/// The attributes exist to carry the shape, not the size: a browser reads them
/// as an aspect ratio and then lays the image out inside whatever the stylesheet
/// allows, so scaling here changes nothing about how the image is drawn and
/// only tells the page how much room to set aside. Dimensions that are missing
/// or nonsensical produce no attributes at all rather than a wrong guess.
pub(super) fn scaled_image_dims(width: Option<i64>, height: Option<i64>, box_px: i64) -> String {
    let (Some(width), Some(height)) = (width, height) else {
        return String::new();
    };
    if width <= 0 || height <= 0 || box_px <= 0 {
        return String::new();
    }
    let long_edge = width.max(height);
    if long_edge <= box_px {
        return format!(r#" width="{width}" height="{height}""#);
    }
    // One edge keeps the box, the other is rounded so the ratio stays honest.
    // The product is widened before it is scaled, because two i64 pixel counts
    // multiplied together overflow far below the sizes involved here, and it is
    // narrowed back afterwards: the result cannot exceed the box it is being
    // scaled into, so the box is the value it falls back to rather than a guess.
    let scaled_short = i64::try_from(
        (i128::from(width.min(height)) * i128::from(box_px)) / i128::from(long_edge),
    )
    .unwrap_or(box_px)
    .max(1);
    let (scaled_width, scaled_height) = if width >= height {
        (box_px, scaled_short)
    } else {
        (scaled_short, box_px)
    };
    format!(r#" width="{scaled_width}" height="{scaled_height}""#)
}

/// Truncates a filename stem without splitting Unicode scalar values.
fn truncate_file_name_stem(input: &str) -> String {
    if input.chars().count() <= FILE_NAME_STEM_PREFIX_DISPLAY_CHARS {
        return input.to_owned();
    }

    let prefix: String = input
        .chars()
        .take(FILE_NAME_STEM_PREFIX_DISPLAY_CHARS)
        .collect();
    format!("{prefix}{FILE_NAME_TRUNCATION_MARKER}")
}

/// Builds a bounded display filename while retaining its extension.
fn display_file_name(name: &str) -> String {
    match name.rfind('.') {
        Some(dot_idx) if dot_idx > 0 => {
            let (stem, ext) = name.split_at(dot_idx);
            if stem.chars().count() > FILE_NAME_STEM_PREFIX_DISPLAY_CHARS {
                format!("{}{}", truncate_file_name_stem(stem), ext)
            } else {
                name.to_owned()
            }
        }
        _ => truncate_file_name_stem(name),
    }
}

/// Renders an escaped download link with the full filename in its tooltip.
fn render_file_link(file_path: &str, file_name: &str) -> String {
    let display_name = display_file_name(file_name);
    format!(
        r#"<a href="/boards/{file_path}" target="_blank" rel="noreferrer" title="{full_name}">{display_name}</a>"#,
        file_path = escape_html(file_path),
        full_name = escape_html(file_name),
        display_name = escape_html(&display_name),
    )
}

/// Resolves media type from the normalized MIME type before stored metadata.
fn effective_media_type(post: &Post) -> crate::models::MediaType {
    if let Some(mime_media) = post
        .mime_type
        .as_deref()
        .map(crate::models::MediaType::from_mime)
        .filter(|media| *media != crate::models::MediaType::Other)
    {
        return mime_media;
    }

    post.media_type.unwrap_or(crate::models::MediaType::Other)
}

/// Render a single post as HTML.
/// `pub` because board.rs uses this for thread-summary preview posts and
/// search results; all other call-sites are within this module.
///
/// # Trust boundary
/// `post.body_html` is inserted **raw** (unescaped) because it is pre-rendered,
/// sanitised HTML produced by the markup pipeline before storage. Every other
/// user-supplied string in this function must continue to pass through
/// `escape_html()`. Do not change the `body_html` insertion without ensuring
/// the upstream sanitiser is still in place.
#[expect(
    clippy::cognitive_complexity,
    reason = "post rendering keeps its security-sensitive escaping and media branches together"
)]
#[expect(
    clippy::too_many_lines,
    reason = "post rendering keeps all media variants and security-sensitive escaping together"
)]
/// First visible character of a poster's name, for the post avatar.
///
/// The avatar is decorative here: a reader who recognizes a name does not need
/// a picture of it, and an account with a real avatar gets that from the
/// account menu instead. It exists so a post still reads as belonging to
/// somebody at a glance.
fn avatar_initial(name: &str) -> String {
    name.trim()
        .chars()
        .find(|character| !character.is_whitespace())
        .map(|character| character.to_uppercase().to_string())
        .unwrap_or_else(|| "#".to_owned())
}

#[must_use]
/// Renders one post: the opening post of a thread, or a reply under it.
///
/// `opts` carries everything that varies between the places a post is shown —
/// whether it is the opening post, whether the reader may act on it, and which
/// account is behind it — so the same markup serves the board index preview,
/// the thread page, and the self-service pages.
pub fn render_post(
    post: &Post,
    board_short: &str,
    csrf_token: &str,
    opts: RenderPostOpts,
    _edit_window_secs: i64,
) -> String {
    let RenderPostOpts {
        show_delete,
        is_admin,
        admin_csrf_token,
        show_media,
        allow_editing,
        allow_self_delete,
        owned_post_controls,
        show_poster_ids,
        collapse_greentext,
        thread_state,
        thread_op_id,
        video_audio_muted,
        vote,
        share_by,
        author,
    } = opts;
    let poster_id = render_poster_id(post, show_poster_ids);
    let poster_id_html = poster_id.as_ref().map_or_else(String::new, |poster_id| {
        let chip_style = poster_id_chip_style(poster_id);
        format!(
            r#" <button type="button" class="poster-id-btn" style="{chip_style}" data-action="toggle-poster-highlight" data-thread-id="{thread_id}" data-poster-id="{poster_id}" disabled>ID: {poster_id}</button>"#,
            chip_style = chip_style,
            thread_id = post.thread_id,
            poster_id = escape_html(poster_id),
        )
    });
    let tripcode_html = post.tripcode.as_deref().map_or_else(String::new, render_tripcode);

    let op_class = if post.is_op { " op" } else { " reply" };
    let poster_attr = poster_id.as_ref().map_or_else(String::new, |poster_id| {
        format!(r#" data-poster-id="{}""#, escape_html(poster_id))
    });

    let subject_html = post.subject.as_ref().map_or_else(String::new, |subject| {
        format!(
            r#"<span class="subject"><strong>{}</strong></span>"#,
            escape_html(subject)
        )
    });
    let post_state_badges = if post.is_op {
        thread_state
            .map(|(sticky, locked, archived)| {
                render_thread_state_badges_full(sticky, locked, archived)
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    let media_processing_badge = match post.media_processing_state.as_deref() {
        Some("pending") => {
            r#" <span class="post-edited" title="Arka plandaki medya işleme hâlâ sürüyor.">(medya işleniyor)</span>"#.to_owned()
        }
        Some("failed") => {
            let title = post
                .media_processing_error
                .as_deref()
                .map_or_else(
                    || "Arka plandaki medya işlemesi başarısız oldu.".to_owned(),
                    escape_html,
                );
            format!(
                r#" <span class="post-edited" title="{title}">(medya işlemesi başarısız)</span>"#
            )
        }
        Some("pruned") => {
            r#" <span class="post-edited" title="Asıl dosya, etkin medya temizliğiyle kaldırıldı.">(asıl dosya kaldırıldı)</span>"#.to_owned()
        }
        _ => String::new(),
    };
    let media_processing_state_attr = post
        .media_processing_state
        .as_deref()
        .map(|state| format!(r#" data-media-processing-state="{}""#, escape_html(state)))
        .unwrap_or_default();

    // An account-backed post is identified by its account, not by the free text
    // in the form: the name links to the profile, the role is shown because a
    // moderator's word should read differently, and the avatar comes from the
    // account. A post written without one falls back to the typed name.
    let (avatar_html, name_html, role_html) = author.as_ref().map_or_else(
        || {
            (
                format!(
                    r#"<span class="post-avatar" aria-hidden="true">{initial}</span>"#,
                    initial = avatar_initial(&post.name),
                ),
                format!(r#"<strong class="name">{name}</strong>"#, name = escape_html(&post.name)),
                String::new(),
            )
        },
        |profile| {
            let avatar = match profile.avatar_file.as_deref() {
                Some(file) if !file.trim().is_empty() => format!(
                    r#"<a class="post-avatar" href="/u/{username}" aria-label="{label} profili"><img src="{file}" alt="" loading="lazy" decoding="async"></a>"#,
                    username = escape_html(&profile.username),
                    label = escape_html(&profile.display_name),
                    file = escape_html(file),
                ),
                _ => format!(
                    r#"<a class="post-avatar is-initial" href="/u/{username}" aria-label="{label} profili">{initial}</a>"#,
                    username = escape_html(&profile.username),
                    label = escape_html(&profile.display_name),
                    initial = avatar_initial(&profile.display_name),
                ),
            };
            let role = if profile.role == crate::roles::UserRole::User {
                String::new()
            } else {
                format!(
                    r#"<span class="post-role" data-role="{role}">{role_label}</span>"#,
                    role = escape_html(profile.role.as_str()),
                    role_label = escape_html(profile.role.label()),
                )
            };
            let name = format!(
                r#"<a class="name" href="/u/{username}">{display}</a>"#,
                username = escape_html(&profile.username),
                display = escape_html(&profile.display_name),
            );
            (avatar, name, role)
        },
    );

    let mut html = format!(
        r##"<div class="post{op_class}" id="p{id}" data-thread-id="{thread_id}"{poster_attr}{media_processing_state_attr}>
<div class="post-head">
{avatar_html}
<div class="post-head-main">
  <div class="post-head-line">
    {name_html}{role_html}{tripcode}{poster_id_html}
    <a class="post-num" href="#p{id}" data-action="append-reply" data-id="{id}">No.{id}</a>{post_state_badges}{media_processing_badge}
  </div>
  <div class="post-head-line post-head-sub">
    <span class="post-time" data-utc="{ts}">{time}</span>
    <span class="backrefs" id="backrefs-{id}"></span>
  </div>
</div>
</div>
{subject_html}"##,
        op_class = op_class,
        id = post.id,
        thread_id = post.thread_id,
        poster_attr = poster_attr,
        media_processing_state_attr = media_processing_state_attr,
        avatar_html = avatar_html,
        name_html = name_html,
        role_html = role_html,
        tripcode = tripcode_html,
        poster_id_html = poster_id_html,
        ts = post.created_at,
        time = fmt_ts_short(post.created_at),
        post_state_badges = post_state_badges,
        media_processing_badge = media_processing_badge,
    );

    // Score, press buttons, and the share line sit together under the header:
    // they are what a reader does with a post, and they belong in the same
    // place on every post whether or not it carries other controls. Both need
    // an account, so a visitor without one is shown neither — and the strip
    // itself is left out rather than left behind empty.
    let permalink = format!("/{board_short}/thread/{tid}#p{pid}",
        board_short = board_short,
        tid = post.thread_id,
        pid = post.id,
    );
    let share_html = render_share_control(share_by.as_deref(), &permalink, post.is_op);
    let vote_html = vote.map_or_else(String::new, |view| {
        render_vote_controls(&view, post.id, csrf_token, &permalink)
    });
    if !vote_html.is_empty() || !share_html.is_empty() {
        html.push_str(&format!(
            r#"<div class="post-social">{vote_html}{share_html}</div>"#,
            vote_html = vote_html,
            share_html = share_html,
        ));
    }

    let primary_media_type = effective_media_type(post);
    let thumb_loading = if post.is_op { "eager" } else { "lazy" };
    let original_pruned =
        post.media_processing_state.as_deref() == Some(crate::db::MEDIA_ORIGINAL_PRUNED);
    // The thumbnail box the stylesheet gives a post's own image, which the
    // reply variant halves. Only the shape is carried, so the exact box only
    // has to be the right shape — but it is read from the post's own image,
    // never from another post's.
    let thumb_dims = if post.media_width.is_some() {
        let reply = !post.is_op;
        scaled_image_dims(
            post.media_width,
            post.media_height,
            if reply { THUMB_REPLY_BOX_PX } else { THUMB_BOX_PX },
        )
    } else {
        String::new()
    };

    // Image / Video / Audio
    if show_media {
        if original_pruned {
            let name_str = post.file_name.as_deref().unwrap_or("dosya");
            let size_str = post.file_size.map(format_file_size).unwrap_or_default();
            let thumb_html = post
                .thumb_path
                .as_deref()
                .map_or_else(String::new, |thumb| {
                    format!(
                        r#"<div class="media-preview media-preview-pruned">{}</div>"#,
                        render_media_thumb(
                            "thumb",
                            "thumb",
                            thumb,
                            "temizlenmiş medya önizlemesi",
                            thumb_loading,
                            "asıl dosya kaldırıldı",
                            &thumb_dims,
                        )
                    )
                });
            let _ = write!(
                html,
                r#"<div class="file-container media-pruned">
<div class="file-info">
  Dosya: <span title="{orig}">{name}</span> ({sz})
  <span class="post-edited" title="Asıl tam boy dosya, etkin medya temizliğiyle kaldırıldı.">asıl dosya kaldırıldı</span>
</div>
{thumb_html}
</div>"#,
                orig = escape_html(name_str),
                name = escape_html(&display_file_name(name_str)),
                sz = escape_html(&size_str),
                thumb_html = thumb_html,
            );
        } else if let (Some(file), Some(thumb)) = (&post.file_path, &post.thumb_path) {
            let size_str = post.file_size.map(format_file_size).unwrap_or_default();
            let name_str = post.file_name.as_deref().unwrap_or("dosya");
            let file_link = render_file_link(file, name_str);
            let mime = post
                .mime_type
                .as_deref()
                .unwrap_or("application/octet-stream");
            let is_audio = matches!(primary_media_type, crate::models::MediaType::Audio);
            let is_video = matches!(primary_media_type, crate::models::MediaType::Video);
            let is_pdf = matches!(primary_media_type, crate::models::MediaType::Pdf);

            let combo_audio = if matches!(primary_media_type, crate::models::MediaType::Image) {
                match (&post.audio_file_path, &post.audio_mime_type) {
                    (Some(aud_file), Some(aud_mime)) => Some((
                        aud_file.as_str(),
                        aud_mime.as_str(),
                        post.audio_file_name.as_deref().unwrap_or("ses"),
                        post.audio_file_size
                            .map(format_file_size)
                            .unwrap_or_default(),
                    )),
                    _ => None,
                }
            } else {
                None
            };

            if is_audio {
                let _ = write!(
                    html,
                    r#"<div class="file-container audio-container">
<div class="file-info">
  Dosya: {file_link} ({sz})
</div>
<div class="audio-thumb">
  {thumb_html}
</div>
<audio controls preload="none" class="audio-player" data-audio-title="{orig}">
  <source src="/boards/{f}" type="{mime}">
  Tarayıcınız ses öğesini desteklemiyor.
</audio>
</div>"#,
                    file_link = file_link,
                    f = escape_html(file),
                    thumb_html = render_media_thumb(
                        "thumb",
                        "thumb",
                        thumb,
                        "ses",
                        thumb_loading,
                        "önizleme kullanılamıyor",
                        &thumb_dims,
                    ),
                    orig = escape_html(name_str),
                    sz = escape_html(&size_str),
                    mime = escape_html(mime)
                );
            } else if is_video {
                let _ = write!(
                    html,
                    r#"<div class="file-container video-container">
<div class="file-info">
  Dosya: {file_link} ({sz})
  <button type="button" class="media-close-btn" data-action="collapse-media" style="display:none" aria-label="Medyayı küçült">&#x2715; kapat</button>
</div>
<a class="media-preview video-preview" data-action="expand-media" href="/boards/{f}" title="oynatmak için tıkla" aria-expanded="false">
  {thumb_html}
  <div class="media-expand-overlay">&#9654;</div>
</a>
<video class="media-expanded media-expanded-video" controls preload="none" playsinline webkit-playsinline{muted_attr} style="display:none">
  <source src="/boards/{f}" type="{mime}">
</video>
</div>"#,
                    file_link = file_link,
                    f = escape_html(file),
                    thumb_html = render_media_thumb(
                        "thumb",
                        "thumb",
                        thumb,
                        "video küçük resmi",
                        thumb_loading,
                        "önizleme kullanılamıyor",
                        &thumb_dims,
                    ),
                    sz = escape_html(&size_str),
                    mime = escape_html(mime),
                    muted_attr = if video_audio_muted { " muted" } else { "" },
                );
            } else if is_pdf {
                let _ = write!(
                    html,
                    r#"<div class="file-container pdf-container">
<div class="file-info">
  Dosya: {file_link} ({sz})
  <button type="button" class="media-close-btn" data-action="collapse-media" style="display:none" aria-label="Medyayı küçült">&#x2715; kapat</button>
</div>
<a class="media-preview pdf-preview" data-action="expand-media" href="/boards/{f}" title="büyütmek için tıkla" aria-expanded="false">
  {thumb_html}
  <div class="media-expand-overlay">&#x2922;</div>
</a>
<iframe class="media-expanded media-expanded-pdf" src="about:blank" data-src="/boards/{f}" title="{orig}" style="display:none"></iframe>
</div>"#,
                    file_link = file_link,
                    f = escape_html(file),
                    thumb_html = render_media_thumb(
                        "thumb",
                        "thumb",
                        thumb,
                        "pdf önizlemesi",
                        thumb_loading,
                        "PDF’yi aç",
                        &thumb_dims,
                    ),
                    sz = escape_html(&size_str),
                    orig = escape_html(name_str)
                );
            } else {
                // Image
                // Keep the preview as an inline expansion control rather than
                // a new tab so a slow JS load or missed handler does not
                // strand the user in a raw-file window.
                let _ = write!(
                    html,
                    r#"<div class="file-container{combo_class}">
<div class="file-info">
  Dosya: {file_link} ({sz})
  <button type="button" class="media-close-btn" data-action="collapse-media" style="display:none" aria-label="Medyayı küçült">&#x2715; kapat</button>
</div>
<a class="media-preview image-preview" data-action="expand-media" href="/boards/{f}" title="büyütmek için tıkla" aria-expanded="false">
  {thumb_html}
  <div class="media-expand-overlay">&#x2922;</div>
</a>
<img class="media-expanded media-expanded-image" src="" data-src="/boards/{f}" style="display:none"
     alt="resim" draggable="false"{full_dims}>
{audio_combo_html}
</div>"#,
                    combo_class = if combo_audio.is_some() {
                        " image-audio-combo"
                    } else {
                        ""
                    },
                    file_link = file_link,
                    f = escape_html(file),
                    thumb_html = render_media_thumb(
                        "thumb",
                        "thumb",
                        thumb,
                        "resim",
                        thumb_loading,
                        "önizleme kullanılamıyor",
                        &thumb_dims,
                    ),
                    full_dims = scaled_image_dims(
                        post.media_width,
                        post.media_height,
                        EXPANDED_IMAGE_BOX_PX,
                    ),
                    sz = escape_html(&size_str),
                    audio_combo_html = combo_audio.map_or_else(
                        String::new,
                        |(aud_file, aud_mime, aud_name, aud_size)| {
                            let audio_link = render_file_link(aud_file, aud_name);
                            format!(
                                r#"<div class="audio-combo audio-combo-inline">
<div class="file-info">
  Ses: {audio_link} ({sz})
</div>
<audio controls preload="none" class="audio-player audio-player-combo" data-audio-title="{orig}" data-artwork-src="/boards/{th}">
  <source src="/boards/{f}" type="{mime}">
  Tarayıcınız ses öğesini desteklemiyor.
</audio>
</div>"#,
                                audio_link = audio_link,
                                f = escape_html(aud_file),
                                th = escape_html(thumb),
                                orig = escape_html(aud_name),
                                sz = escape_html(&aud_size),
                                mime = escape_html(aud_mime)
                            )
                        }
                    )
                );
            }
        } else if let Some(file) = &post.file_path {
            let size_str = post.file_size.map(format_file_size).unwrap_or_default();
            let name_str = post.file_name.as_deref().unwrap_or("dosya");
            let file_link = render_file_link(file, name_str);
            let status_note = match post.media_processing_state.as_deref() {
                Some("pending") => "Önizleme hâlâ işleniyor.",
                Some("failed") => "Önizleme oluşturulamadı; asıl dosya hâlâ kullanılabilir.",
                _ => "Önizleme kullanılamıyor.",
            };
            let _ = write!(
                html,
                r#"<div class="file-container">
<div class="file-info">
  Dosya: {file_link} ({sz})
  <span class="post-edited" title="{status}">{status}</span>
</div>
</div>"#,
                file_link = file_link,
                sz = escape_html(&size_str),
                status = escape_html(status_note),
            );
        }
    }

    if show_media
        && !original_pruned
        && matches!(&post.media_type, Some(crate::models::MediaType::Other))
    {
        if let Some(file) = &post.file_path {
            let size_str = post.file_size.map(format_file_size).unwrap_or_default();
            let name_str = post.file_name.as_deref().unwrap_or("indirme");
            let file_link = render_file_link(file, name_str);
            let _ = write!(
                html,
                r#"<div class="file-container file-download">
<div class="file-info">
  Dosya: {file_link} ({sz})
</div>
</div>"#,
                file_link = file_link,
                sz = escape_html(&size_str)
            );
        }
    }

    // Secondary audio fallback for legacy rows that store a separate audio attachment.
    if show_media
        && !original_pruned
        && !matches!(primary_media_type, crate::models::MediaType::Image)
    {
        if let (Some(aud_file), Some(aud_mime)) = (&post.audio_file_path, &post.audio_mime_type) {
            let aud_name = post.audio_file_name.as_deref().unwrap_or("ses");
            let aud_size = post
                .audio_file_size
                .map(format_file_size)
                .unwrap_or_default();
            let audio_link = render_file_link(aud_file, aud_name);
            let _ = write!(
                html,
                r#"<div class="file-container audio-container audio-combo">
<div class="file-info">
  File: {audio_link} ({sz})
</div>
<audio controls preload="none" class="audio-player" data-audio-title="{orig}">
  <source src="/boards/{f}" type="{mime}">
  Tarayıcınız ses öğesini desteklemiyor.
</audio>
</div>"#,
                audio_link = audio_link,
                f = escape_html(aud_file),
                orig = escape_html(aud_name),
                sz = escape_html(&aud_size),
                mime = escape_html(aud_mime)
            );
        }
    }

    // Post body (pre-rendered, sanitised HTML)
    let body_html =
        crate::utils::sanitize::normalize_greentext_blocks(&post.body_html, collapse_greentext);
    let body_html = annotate_op_quotelinks(&body_html, thread_op_id);
    let _ = write!(html, r#"<div class="post-body">{body_html}</div>"#);

    // Edit link + report button (only on thread pages where show_delete=true)
    if show_delete {
        let now = chrono::Utc::now().timestamp();
        let self_action_controls = owned_post_controls
            .as_ref()
            .filter(|controls| controls.expires_at > now)
            .map_or_else(String::new, |controls| {
                let edit_button = if allow_editing {
                    format!(
                        r#"<a class="edit-btn" href="/{board}/post/{pid}/edit" data-action="open-edit-modal" data-edit-post-id="{pid}" data-edit-expiry="{expires_at}" title="Gönderiyi düzenle" aria-haspopup="dialog">düzenle</a>
<textarea id="edit-body-{pid}" data-role="edit-body-source" hidden>{body}</textarea>"#,
                        board = escape_html(board_short),
                        pid = post.id,
                        expires_at = controls.expires_at,
                        body = escape_html(&post.body),
                    )
                } else {
                    String::new()
                };
                let delete_button = if allow_self_delete {
                    format!(
                        r#"<a class="del-btn" href="/{board}/post/{pid}/delete" data-confirm="No.{pid} numaralı gönderin silinsin mi?" data-delete-csrf="{csrf}">sil</a>"#,
                        board = escape_html(board_short),
                        pid = post.id,
                        csrf = escape_html(csrf_token),
                    )
                } else {
                    String::new()
                };
                if edit_button.is_empty() && delete_button.is_empty() {
                    String::new()
                } else {
                    format!(
                        r#" <span class="self-action-controls" data-action-expiry="{expires_at}">{edit_button}{delete_button}{window_hint}</span>"#,
                        expires_at = controls.expires_at,
                        edit_button = edit_button,
                        delete_button = delete_button,
                        window_hint = render_self_action_window_hint(controls.expires_at),
                    )
                }
            });

        let report_btn = format!(
            r#" <button type="button" class="report-btn"
                data-action="open-report" data-pid="{pid}" data-tid="{tid}" data-board="{board}" data-csrf="{csrf}">şikayet et</button>"#,
            pid = post.id,
            tid = post.thread_id,
            board = escape_html(board_short),
            csrf = escape_html(csrf_token),
        );
        let report_fallback = super::report_fallback_form(
            board_short,
            post.id,
            post.thread_id,
            csrf_token,
            "şikayet gönder",
        );

        let _ = write!(
            html,
            r#"<div class="post-controls">{self_action_controls}{report_btn}{report_fallback}</div>"#
        );
    }

    // Admin delete button + IP history/report links
    if is_admin {
        let is_op_val = if post.is_op { "1" } else { "0" };
        let return_to = format!("/{}/thread/{}", board_short, post.thread_id);
        let admin_form_csrf = admin_csrf_token.as_deref().unwrap_or(csrf_token);
        let _ = write!(
            html,
            r#"<div class="post-controls admin-post-controls">
<form method="POST" action="/admin/post/delete">
<input type="hidden" name="_csrf"   value="{csrf}">
<input type="hidden" name="post_id" value="{pid}">
<input type="hidden" name="board"   value="{board}">
<button type="submit" class="admin-del-btn"
        data-confirm="No.{pid} gönderisi yönetici tarafından silinsin mi?">&#x2715; sil</button>
</form>
<form method="POST" action="/admin/post/ban-delete"
      data-ban-delete-pid="{pid}">
<input type="hidden" name="_csrf"      value="{csrf}">
<input type="hidden" name="post_id"    value="{pid}">
<input type="hidden" name="ip_hash"    value="{ip_hash}">
<input type="hidden" name="board"      value="{board}">
<input type="hidden" name="thread_id"  value="{tid}">
<input type="hidden" name="is_op"      value="{is_op}">
<input type="hidden" name="reason"     id="ban-reason-{pid}" value="">
<input type="hidden" name="duration_hours" id="ban-dur-{pid}" value="0">
<button type="submit" class="admin-del-btn btn-danger">&#x26D4; yasakla+sil</button>
</form>
<a class="admin-ip-link" href="/admin/ip/{ip_hash}?return_to={return_to}" title="Bu karma IP’den tüm gönderileri gör">&#x1F50D; ip</a>
</div>"#,
            csrf = escape_html(admin_form_csrf),
            pid = post.id,
            board = escape_html(board_short),
            ip_hash = escape_html(post.ip_hash.as_deref().unwrap_or("")),
            tid = post.thread_id,
            return_to = encode_query_component(&return_to),
            is_op = is_op_val
        );
    }

    html.push_str("</div>\n");
    html
}

/// Renders the shared in-page edit dialog and optional validation state.
fn render_edit_overlay(
    board: &Board,
    thread_id: i64,
    csrf_token: &str,
    edit_overlay_state: Option<&EditOverlayState>,
) -> String {
    let (post_id, current_body, error_html, modal_class) = edit_overlay_state.map_or_else(
        || {
            (
                0,
                "",
                String::from(
                    r#"<div class="post-error-banner edit-modal-error" data-role="edit-modal-error" hidden></div>"#,
                ),
                "edit-modal",
            )
        },
        |state| {
            (
            state.post_id,
            state.body.as_str(),
            state
                .error
                .as_deref()
                .map(|msg| {
                    format!(
                        r#"<div class="post-error-banner edit-modal-error" data-role="edit-modal-error">&#9888; {}</div>"#,
                        escape_html(msg)
                    )
                })
                .unwrap_or_default(),
            "edit-modal is-open",
            )
        },
    );
    let aria_hidden = if edit_overlay_state.is_some() {
        "false"
    } else {
        "true"
    };
    let hidden_attr = if edit_overlay_state.is_some() {
        ""
    } else {
        " hidden inert"
    };

    format!(
        r#"<div id="edit-modal" class="{modal_class}" data-thread-id="{thread_id}" data-board="{board}" aria-hidden="{aria_hidden}"{hidden_attr}>
  <div class="edit-modal-backdrop" data-action="close-edit-modal"></div>
  <div class="edit-modal-box" role="dialog" aria-modal="true" aria-labelledby="edit-modal-title">
    <div class="post-form-title" id="edit-modal-title">[ gönderini düzenle <span class="self-delete-countdown" data-role="edit-modal-countdown" aria-live="polite"></span> ]</div>
    {error_html}
    <form id="edit-modal-form" class="post-form" method="POST" action="/{board}/post/{post_id}/edit">
      <input type="hidden" name="_csrf" value="{csrf}">
      <input type="hidden" name="thread_id" value="{thread_id}">
      <table>
        <tr><td>gövde</td>
            <td><textarea id="edit-modal-body" name="body" aria-label="gönderi metnini düzenle" rows="6" maxlength="4096">{current_body}</textarea></td></tr>
        <tr><td></td>
            <td><button type="submit">düzenlemeyi kaydet</button>
                <button type="button" class="edit-btn" data-action="close-edit-modal" style="margin-left:1rem">vazgeç</button></td></tr>
      </table>
    </form>
  </div>
</div>"#,
        modal_class = modal_class,
        thread_id = thread_id,
        board = escape_html(&board.short_name),
        aria_hidden = aria_hidden,
        hidden_attr = hidden_attr,
        error_html = error_html,
        post_id = post_id,
        csrf = escape_html(csrf_token),
        current_body = escape_html(current_body),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        delete_post_page, display_file_name, edit_post_page, render_post, render_vote_controls,
        scaled_image_dims, thread_page, EditOverlayState, OwnedPostControls, RenderPostOpts,
    };
    use crate::models::{BoardAccessMode, MediaType, Post, Thread};

    #[test]
    /// The attributes only have to carry the shape. A large image is scaled to
    /// the box it will be drawn in, and the ratio it lands on is the ratio the
    /// browser will apply, so nothing about the drawn size is decided here.
    fn dimensions_scale_to_the_box_and_keep_their_ratio() {
        assert_eq!(
            scaled_image_dims(Some(4000), Some(3000), 150),
            r#" width="150" height="112""#,
            "a wide image is capped by its long edge and the short one follows"
        );
        assert_eq!(
            scaled_image_dims(Some(3000), Some(4000), 150),
            r#" width="112" height="150""#,
            "a tall image is capped the other way round"
        );
        assert_eq!(
            scaled_image_dims(Some(100), Some(80), 150),
            r#" width="100" height="80""#,
            "an image that already fits is left at its own size"
        );
    }

    #[test]
    /// A post written before dimensions were recorded has none, and inventing
    /// some would reserve the wrong space. So an unknown shape reserves
    /// nothing at all, and a nonsensical one is treated the same way.
    fn unknown_or_nonsensical_dimensions_reserve_nothing() {
        assert_eq!(scaled_image_dims(None, None, 150), "");
        assert_eq!(
            scaled_image_dims(Some(100), None, 150),
            "",
            "half an answer is not an answer"
        );
        assert_eq!(
            scaled_image_dims(Some(0), Some(100), 150),
            "",
            "an image with no width is not an image"
        );
        assert_eq!(
            scaled_image_dims(Some(-10), Some(100), 150),
            "",
            "a negative width is not a width"
        );
    }

    #[test]
    /// A very thin sliver rounds to at least one pixel rather than to nothing,
    /// because a zero height would tell the browser the image is a line and
    /// reserve no space at all.
    fn a_sliver_still_reserves_at_least_one_pixel() {
        assert_eq!(
            scaled_image_dims(Some(10_000), Some(1), 150),
            r#" width="150" height="1""#
        );
    }

    fn sample_post() -> Post {
        Post {
            id: 1,
            thread_id: 1,
            board_id: 1,
            name: "anon".into(),
            tripcode: None,
            subject: None,
            body: "body".into(),
            body_html: "body".into(),
            ip_hash: Some("hash".into()),
            file_path: Some("test/image.webp".into()),
            file_name: Some("image.webp".into()),
            file_size: Some(1024),
            thumb_path: Some("test/thumbs/image.webp".into()),
            mime_type: Some("image/webp".into()),
            media_type: Some(MediaType::Image),
            audio_file_path: None,
            audio_file_name: None,
            audio_file_size: None,
            audio_mime_type: None,
            created_at: 1_700_000_000,
            deletion_token: "token".into(),
            is_op: false,
            edited_at: None,
            media_processing_state: None,
            media_processing_error: None,
            user_id: None,
            media_width: None,
            media_height: None,
        }
    }

    fn sample_thread() -> Thread {
        Thread {
            id: 87,
            board_id: 1,
            subject: Some("Thread subject".into()),
            created_at: 1_700_000_000,
            bumped_at: 1_700_000_100,
            locked: false,
            sticky: false,
            archived: false,
            reply_count: 12,
            image_count: 3,
            op_body: Some("Thread body preview".into()),
            op_file: Some("test/image.webp".into()),
            op_thumb: Some("test/thumbs/image.webp".into()),
            op_name: Some("anon".into()),
            op_tripcode: None,
            op_media_width: None,
            op_media_height: None,
            author_user_id: None,
            author_username: None,
            author_display_name: None,
            author_avatar_file: None,
            op_id: Some(1),
        }
    }

    #[test]
    fn thread_page_renders_thread_nav_links_and_reply_open_action() {
        let board = crate::test_fixtures::sample_board();
        let thread = sample_thread();
        let posts = vec![Post {
            is_op: true,
            ..sample_post()
        }];

        let html = thread_page((
        &board,
        &thread,
        &posts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(html.contains(r#"href="/test">[ Geri ]</a>"#));
        assert!(html.contains(r#"href="/test/catalog">[ Katalog ]</a>"#));
        assert!(html.contains(r##"href="#bottom">[ Sona ]</a>"##));
        assert!(html.contains(r##"href="#top">[ Başa ]</a>"##));
        assert!(html.contains(r#"data-activity-page="thread""#));
        assert!(html.contains(r#"data-action="toggle-post-form""#));
    }

    #[test]
    fn thread_page_renders_access_gate_when_posting_is_locked_behind_password() {
        let board = crate::models::Board {
            access_mode: BoardAccessMode::PostPassword,
            access_password_hash: "hash".into(),
            ..crate::test_fixtures::sample_board()
        };
        let thread = sample_thread();
        let posts = vec![Post {
            is_op: true,
            ..sample_post()
        }];

        let html = thread_page((
        &board,
        &thread,
        &posts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(html.contains(r#"href="/test">[ Geri ]</a>"#));
        assert!(html.contains(r#"href="/test/catalog">[ Katalog ]</a>"#));
        assert!(html.contains(r#"id="board-access-gate""#));
        assert!(html.contains(
            r#"name="password" aria-label="board parolası" maxlength="256" autocomplete="current-password" required"#
        ));
    }

    #[test]
    fn thread_page_admin_forms_use_admin_csrf_token() {
        let board = crate::test_fixtures::sample_board();
        let thread = sample_thread();
        let posts = vec![Post {
            is_op: true,
            ip_hash: Some("a".repeat(64)),
            ..sample_post()
        }];

        let html = thread_page((
        &board,
        &thread,
        &posts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "public-csrf",
            std::slice::from_ref(&board),
            true,
            Some("admin-csrf"),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(html.contains(r#"action="/admin/thread/delete""#));
        assert!(html.contains(r#"action="/admin/post/delete""#));
        assert!(html.contains(r#"name="_csrf" value="admin-csrf""#));
        assert!(html.contains(r#"name="_csrf"   value="admin-csrf""#));
        assert!(html.contains(r#"data-csrf="public-csrf""#));
    }

    #[test]
    fn render_post_includes_no_js_report_fallback_form() {
        let post = sample_post();

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: true,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains(r#"class="report-btn""#));
        assert!(html.contains(r#"data-action="open-report""#));
        assert!(html.contains(r#"class="report-fallback-form" method="POST" action="/report""#));
        assert!(html.contains(r#"name="_csrf" value="csrf""#));
        assert!(html.contains(r#"name="post_id" value="1""#));
        assert!(html.contains(r#"name="thread_id" value="1""#));
        assert!(html.contains(r#"name="board" value="test""#));
    }

    #[test]
    fn render_post_uses_persisted_transcoded_file_size() {
        let post = Post {
            file_path: Some("test/video.webm".into()),
            file_name: Some("video.mp4".into()),
            file_size: Some(4),
            thumb_path: Some("test/thumbs/video.webp".into()),
            mime_type: Some("video/webm".into()),
            media_type: Some(MediaType::Video),
            ..sample_post()
        };

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains("video-container"));
        assert!(html.contains("(4 B)"));
        assert!(!html.contains("(1.0 KiB)"));
    }

    #[test]
    fn neutral_webm_fallback_never_renders_as_video() {
        let post = Post {
            file_path: Some("test/ambiguous.bin".into()),
            file_name: Some("ambiguous.webm".into()),
            thumb_path: None,
            mime_type: Some("application/octet-stream".into()),
            media_type: Some(MediaType::Other),
            ..sample_post()
        };

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains("file-download"));
        assert!(!html.contains("video-container"));
        assert!(!html.contains("<video"));
    }

    #[test]
    fn image_audio_combo_renders_single_media_box_with_inline_audio() {
        let mut post = sample_post();
        post.audio_file_path = Some("test/song.flac".into());
        post.audio_file_name = Some("song.flac".into());
        post.audio_file_size = Some(2048);
        post.audio_mime_type = Some("audio/flac".into());

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains("file-container image-audio-combo"));
        assert!(html.contains(r#"Ses: <a href="/boards/test/song.flac""#));
        assert!(html.contains(r#"data-artwork-src="/boards/test/thumbs/image.webp""#));
        assert!(!html.contains("file-container audio-container audio-combo"));
    }

    #[test]
    fn contradictory_image_mime_prefers_combo_render_over_standalone_audio_boxes() {
        let mut post = sample_post();
        post.file_path = Some("test/confused.png".into());
        post.file_name = Some("confused.png".into());
        post.thumb_path = Some("test/thumbs/confused.png".into());
        post.mime_type = Some("image/png".into());
        post.media_type = Some(MediaType::Audio);
        post.audio_file_path = Some("test/song.mp3".into());
        post.audio_file_name = Some("song.mp3".into());
        post.audio_file_size = Some(2048);
        post.audio_mime_type = Some("audio/mpeg".into());

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains("file-container image-audio-combo"));
        assert!(html.contains(r#"Ses: <a href="/boards/test/song.mp3""#));
        assert!(html.contains(r#"class="audio-player audio-player-combo""#));
        assert!(!html.contains("file-container audio-container audio-combo"));
        assert!(!html.contains(r#"class="audio-player" data-audio-title="song.mp3""#));
    }

    #[test]
    fn display_file_name_truncates_long_stems_and_keeps_extension() {
        assert_eq!(
            display_file_name("A412BB86-098B-48D1-7DG12GNY78KS.jpg"),
            "A412BB86-098B-48D1-7(...).jpg"
        );
        assert_eq!(display_file_name("short.webp"), "short.webp");
        assert_eq!(
            display_file_name("1234567890123456789012345"),
            "12345678901234567890(...)"
        );
    }

    #[test]
    fn render_post_uses_truncated_filename_with_full_title() {
        let mut post = sample_post();
        post.file_name = Some("supercalifragilisticx.webp".into());

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html
            .contains(r#"title="supercalifragilisticx.webp">supercalifragilistic(...).webp</a>"#));
    }

    #[test]
    fn op_post_uses_archive_badge_instead_of_lock_badge_for_archived_threads() {
        let mut post = sample_post();
        post.is_op = true;

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: false,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: Some((true, true, true)),
                thread_op_id: Some(post.id),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains("thread-state-badge-pin"));
        assert!(html.contains("thread-state-badge-archive"));
        assert!(!html.contains("thread-state-badge-lock"));
    }

    #[test]
    fn media_processing_failure_renders_fallback_when_thumb_is_missing() {
        let mut post = sample_post();
        post.thumb_path = None;
        post.media_processing_state = Some("failed".into());
        post.media_processing_error = Some("Queue exhausted retries".into());

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains("medya işlemesi başarısız"));
        assert!(html.contains("Önizleme oluşturulamadı; asıl dosya hâlâ kullanılabilir."));
        assert!(html.contains(r#"href="/boards/test/image.webp""#));
    }

    #[test]
    fn pruned_original_renders_thumbnail_without_original_link() {
        let mut post = sample_post();
        post.media_processing_state = Some(crate::db::MEDIA_ORIGINAL_PRUNED.into());
        post.media_processing_error = Some("asıl dosya kaldırıldı".into());

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains("asıl dosya kaldırıldı"));
        assert!(html.contains("/boards/test/thumbs/image.webp"));
        assert!(!html.contains(r#"href="/boards/test/image.webp""#));
        assert!(!html.contains(r#"data-src="/boards/test/image.webp""#));
    }

    #[test]
    fn pruned_generic_download_does_not_render_stale_download_link() {
        let mut post = sample_post();
        post.file_path = Some("test/archive.zip".into());
        post.file_name = Some("archive.zip".into());
        post.thumb_path = None;
        post.mime_type = Some("application/zip".into());
        post.media_type = Some(MediaType::Other);
        post.media_processing_state = Some(crate::db::MEDIA_ORIGINAL_PRUNED.into());
        post.media_processing_error = Some("asıl dosya kaldırıldı".into());

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains("asıl dosya kaldırıldı"));
        assert!(!html.contains(r#"href="/boards/test/archive.zip""#));
    }

    #[test]
    /// A recorded image reserves its space on both the thumbnail and the
    /// expanded view, so the thread does not jump as either one loads.
    fn a_recorded_image_reserves_its_space_on_the_page() {
        let mut post = sample_post();
        post.media_width = Some(4000);
        post.media_height = Some(3000);

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(
            html.contains(r#"data-media-thumb="1" width="80" height="60""#),
            "a reply thumbnail must declare the shape it will occupy"
        );
        assert!(
            html.contains(r#"width="640" height="480""#),
            "the expanded image must declare the shape it will occupy"
        );
    }

    #[test]
    /// A post with no recorded dimensions renders exactly as it did before
    /// dimensions existed, rather than declaring a shape nobody measured.
    fn a_post_without_recorded_dimensions_declares_none() {
        let post = sample_post();

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(
            html.contains(r#"data-media-thumb="1">"#),
            "an unknown shape must not be invented"
        );
    }

    #[test]
    fn media_thumb_markup_includes_hidden_fallback_for_missing_assets() {
        let post = sample_post();

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains(r#"data-media-thumb="1""#));
        assert!(html.contains(r#"loading="lazy" decoding="async""#));
        assert!(html.contains("media-thumb-fallback"));
    }

    #[test]
    fn op_media_stays_eager_while_reply_media_is_lazy() {
        let mut op = sample_post();
        op.is_op = true;
        let op_html = render_post(
            &op,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );
        assert!(op_html.contains(r#"loading="eager" decoding="async""#));

        let reply_html = render_post(
            &sample_post(),
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );
        assert!(reply_html.contains(r#"loading="lazy" decoding="async""#));
    }

    #[test]
    fn pdf_post_renders_thumbnail_direct_link_and_inline_hooks() {
        let mut post = sample_post();
        post.file_path = Some("test/doc.pdf".into());
        post.file_name = Some("doc.pdf".into());
        post.thumb_path = Some("test/thumbs/doc.webp".into());
        post.mime_type = Some("application/pdf".into());
        post.media_type = Some(MediaType::Pdf);

        let html = render_post(
            &post,
            "test",
            "csrf",
            RenderPostOpts {
                show_delete: false,
                is_admin: false,
                admin_csrf_token: None,
                show_media: true,
                allow_editing: false,
                allow_self_delete: false,
                owned_post_controls: None,
                vote: None,
                share_by: None,
                author: None,
                show_poster_ids: false,
                collapse_greentext: true,
                thread_state: None,
                thread_op_id: Some(1),
                video_audio_muted: false,
            },
            0,
        );

        assert!(html.contains(r#"href="/boards/test/doc.pdf""#));
        assert!(html.contains(r#"src="/boards/test/thumbs/doc.webp""#));
        assert!(html.contains(r#"data-action="expand-media""#));
        assert!(html.contains(r#"data-action="collapse-media""#));
        assert!(html.contains(r#"<iframe class="media-expanded media-expanded-pdf""#));
        assert!(html.contains(r#"data-src="/boards/test/doc.pdf""#));
        assert!(html.contains("PDF’yi aç"));
        assert!(!html.contains(">PDF</div>"));
        assert!(!html.contains("post-edited\">PDF’yi aç"));
    }

    #[test]
    fn a_vote_press_carries_the_direction_it_stands_for() {
        let html = render_vote_controls(
            &crate::db::PostVoteView {
                score: 3,
                my_vote: 1,
            },
            42,
            "csrf-token",
            "/b/thread/7#p42",
        );

        // A submit button with no `name` sends nothing, and the form arrives
        // without the one field that says which arrow was pressed.
        assert!(
            html.contains(r#"<button type="submit" name="value" value="1""#),
            "the upvote must say which direction it stands for"
        );
        assert!(
            html.contains(r#"<button type="submit" name="value" value="-1""#),
            "the downvote must say which direction it stands for"
        );
        assert!(
            html.contains(r#"name="post_id" value="42""#),
            "the press must name the post it is about"
        );
        assert!(html.contains(">3</output>"), "the score must be shown");
    }

    #[test]
    fn the_pressed_arrow_is_marked_so_the_press_can_be_repeated_to_undo_it() {
        let up = render_vote_controls(
            &crate::db::PostVoteView {
                score: 1,
                my_vote: 1,
            },
            1,
            "csrf",
            "/b/thread/1#p1",
        );
        assert!(up.contains(r#"class="vote-btn vote-up is-active""#));
        assert!(up.contains(r#"class="vote-btn vote-down""#));
    }

    #[test]
    fn thread_page_reopens_reply_form_with_prefill_on_error() {
        let board = crate::test_fixtures::sample_board();
        let thread = sample_thread();
        let posts = vec![Post {
            is_op: true,
            ..sample_post()
        }];
        let reply_prefill = crate::templates::forms::PostFormState {
            body: "retry reply".into(),
            sage: true,
            ..crate::templates::forms::PostFormState::default()
        };

        let html = thread_page((
        &board,
        &thread,
        &posts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            Some("Wait before posting"),
            None,
            Some(&reply_prefill),
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(html.contains(r#"class="post-form-wrap is-open""#));
        assert!(html.contains(">retry reply</textarea>"));
        assert!(html.contains(r#"name="sage" value="1" checked"#));
    }

    #[test]
    fn thread_page_renders_edit_overlay_with_submitted_body_and_error() {
        let board = crate::test_fixtures::sample_board();
        let post = sample_post();
        let mut owned = std::collections::BTreeMap::new();
        owned.insert(
            post.id,
            OwnedPostControls {
                expires_at: i64::MAX,
            },
        );

        let html = thread_page((
        &board,
        &sample_thread(),
        std::slice::from_ref(&post),
            &owned,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            Some(&EditOverlayState {
                post_id: post.id,
                body: "edited draft".into(),
                error: Some("Edit failed.".into()),
            }),
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(html.contains(r#"id="edit-modal""#));
        assert!(html.contains(r#"class="edit-modal is-open""#));
        assert!(html.contains(">edited draft</textarea>"));
        assert!(html.contains("Edit failed."));
    }

    #[test]
    fn thread_page_includes_admin_ban_delete_modal_only_for_admin() {
        let board = crate::test_fixtures::sample_board();
        let post = sample_post();

        let admin_html = thread_page((
        &board,
        &sample_thread(),
        std::slice::from_ref(&post),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            true,
            Some("admin-csrf"),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(admin_html.contains(r#"id="ban-delete-modal""#));
        assert!(admin_html.contains(r#"for="ban-delete-reason""#));
        assert!(admin_html.contains(r#"for="ban-delete-duration""#));

        let public_html = thread_page((
        &board,
        &sample_thread(),
        std::slice::from_ref(&post),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(!public_html.contains(r#"id="ban-delete-modal""#));
    }

    #[test]
    fn render_post_uses_in_page_edit_action_without_tokenized_redirect() {
        let mut board = crate::test_fixtures::sample_board();
        board.allow_editing = true;
        board.allow_self_delete = true;
        let mut post = sample_post();
        post.created_at = chrono::Utc::now().timestamp();

        let html = thread_page((
        &board,
        &sample_thread(),
        std::slice::from_ref(&post),
            &std::collections::BTreeMap::from([(
                post.id,
                OwnedPostControls {
                    expires_at: i64::MAX,
                },
            )]),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(html.contains(r#"href="/test/post/1/edit""#));
        assert!(html.contains(r#"class="self-action-controls""#));
        assert!(html.contains(r#"class="edit-btn""#));
        assert!(html.contains(r#"class="del-btn""#));
        assert!(html.contains(r#"data-action="open-edit-modal""#));
        assert!(html.contains(r#"data-edit-expiry=""#));
        assert!(html.contains(r#"data-delete-csrf=""#));
        assert!(html.contains(r#"data-role="self-action-countdown""#));
        assert!(html.contains(r#"href="/test/post/1/delete""#));
        assert!(html.contains("gönderdikten sonra en fazla 60 saniye boyunca kullanılabilir"));
        assert!(!html.contains("?token="));

        let expiry_attr = r#"data-action-expiry=""#;
        let expiry_value = html
            .split_once(expiry_attr)
            .and_then(|(_, suffix)| suffix.split_once('"').map(|(value, _)| value));
        let expiry = expiry_value.and_then(|value| value.parse::<i64>().ok());
        assert!(
            expiry_value.is_some(),
            "expiry attribute should have a closing quote"
        );
        assert!(expiry.is_some(), "expiry should be parseable");
        assert!(expiry.is_some_and(|value| value > 0));
    }

    #[test]
    /// Matches owner controls to the server's closed-thread and OP-deletion rules.
    fn thread_page_hides_unavailable_owned_controls() {
        let board = crate::models::Board {
            allow_editing: true,
            allow_self_delete: true,
            ..crate::test_fixtures::sample_board()
        };
        let post = Post {
            is_op: true,
            ..sample_post()
        };
        let controls = std::collections::BTreeMap::from([(
            post.id,
            OwnedPostControls {
                expires_at: i64::MAX,
            },
        )]);
        for (locked, archived, replies, can_edit, can_delete) in [
            (false, false, 0, true, true),
            (true, false, 0, false, false),
            (false, true, 0, false, false),
            (false, false, 1, true, false),
        ] {
            let thread = Thread {
                locked,
                archived,
                reply_count: replies,
                ..sample_thread()
            };
            let html = thread_page((
            &board,
            &thread,
            std::slice::from_ref(&post),
                &controls,
                &std::collections::BTreeMap::new(),
                &std::collections::BTreeMap::new(),
                "csrf",
                std::slice::from_ref(&board),
                false,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                true,
                crate::templates::UserPreferences::default(),
            None,
            "",
        ));
            assert_eq!(html.contains(r#"data-action="open-edit-modal""#), can_edit);
            assert_eq!(html.contains(r#"class="del-btn""#), can_delete);
            assert!(html.contains(&format!(r#"data-locked="{locked}""#)));
            assert!(html.contains(&format!(r#"data-archived="{archived}""#)));
        }
    }

    #[test]
    fn edit_post_page_renders_normal_form_and_fallback_hint() {
        let board = crate::test_fixtures::sample_board();
        let thread = sample_thread();
        let post = sample_post();

        let html = edit_post_page(
            &board,
            &thread,
            &post,
            "csrf",
            std::slice::from_ref(&board),
            None,
            None,
        );

        assert!(html.contains(r#"method="POST" action="/test/post/1/edit""#));
        assert!(html.contains(r#"name="_csrf" value="csrf""#));
        assert!(html.contains(
            r#"name="body" aria-label="gönderi metnini düzenle" rows="8" maxlength="4096" required"#
        ));
        assert!(html.contains("gönderdikten sonra en fazla 60 saniye boyunca kullanılabilir"));
        assert!(html.contains(r#"href="/test/thread/87#p1""#));
    }

    #[test]
    fn delete_post_page_renders_normal_form_and_fallback_hint() {
        let board = crate::test_fixtures::sample_board();
        let thread = sample_thread();
        let post = sample_post();

        let html = delete_post_page(
            &board,
            &thread,
            &post,
            "csrf",
            std::slice::from_ref(&board),
            None,
            None,
        );

        assert!(html.contains(r#"method="POST" action="/test/post/1/delete""#));
        assert!(html.contains(r#"name="_csrf" value="csrf""#));
        assert!(html.contains(r#"class="del-btn">gönderiyi sil</button>"#));
        assert!(html.contains("gönderdikten sonra en fazla 60 saniye boyunca kullanılabilir"));
        assert!(html.contains(r#"href="/test/thread/87#p1""#));
    }

    #[test]
    fn render_post_hides_edited_badge_for_edited_posts() {
        let mut board = crate::test_fixtures::sample_board();
        board.allow_editing = true;
        let mut post = sample_post();
        post.created_at = chrono::Utc::now().timestamp();
        post.edited_at = Some(post.created_at + 5);

        let html = thread_page((
        &board,
        &sample_thread(),
        std::slice::from_ref(&post),
            &std::collections::BTreeMap::from([(
                post.id,
                OwnedPostControls {
                    expires_at: i64::MAX,
                },
            )]),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(!html.contains("(edited"));
    }

    #[test]
    /// The two arrows and the score are real form controls, so a reader with
    /// scripting off votes exactly the same way. The arrow that is already
    /// pressed is rendered as pressed, and it is the same form that takes the
    /// vote back: the pressed state is the only difference, and there is no
    /// third "remove" control to find.
    fn a_post_shows_its_score_and_which_arrow_is_pressed() {
        let board = crate::test_fixtures::sample_board();
        let mut post = sample_post();
        post.thread_id = 87;
        let posts = vec![post.clone()];
        let account = crate::templates::auth::AccountMenu {
            display_name: "Rain".to_owned(),
            username: "rainkawa".to_owned(),
            is_admin: false,
            user_id: None,
            avatar_file: None,
        };
        let votes = std::collections::BTreeMap::from([(
            post.id,
            crate::db::PostVoteView {
                score: 7,
                my_vote: -1,
            },
        )]);

        let html = thread_page((
            &board,
            &sample_thread(),
            &posts,
            &std::collections::BTreeMap::new(),
            &votes,
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            Some(&account),
            "",
        ));

        assert!(
            html.contains(r#"class="post-vote" method="POST" action="/post-vote""#),
            "voting must work as a form, not only through scripting: {html}"
        );
        assert!(
            html.contains(r#"class="vote-score" title="Beğeni puanı">7<"#),
            "the score must be shown: {html}"
        );
        assert!(
            html.contains(r#"class="vote-btn vote-down is-active""#),
            "the pressed arrow must look pressed: {html}"
        );
        assert!(
            html.contains(r#"class="vote-btn vote-up""#),
            "an unpressed arrow must not look pressed: {html}"
        );

        let anonymous = thread_page((
            &board,
            &sample_thread(),
            &posts,
            &std::collections::BTreeMap::new(),
            &votes,
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));
        assert!(
            !anonymous.contains("post-vote"),
            "a vote needs an account, so a reader with none is shown no arrows: {anonymous}"
        );
        assert!(
            !anonymous.contains(">7<"),
            "a score is not shown without the arrows that earned it: {anonymous}"
        );
    }

    #[test]
    /// A share is named after the account behind the post, and the link is
    /// shown as text rather than hidden behind a button, because a board is
    /// shared by copying a line. The name links to that account's profile, so
    /// the reader can get from a share to the account that made it.
    fn a_share_names_the_account_behind_the_post_and_links_to_its_profile() {
        let board = crate::test_fixtures::sample_board();
        let mut op = sample_post();
        op.is_op = true;
        op.thread_id = 87;
        let mut reply = sample_post();
        reply.id = 2;
        reply.thread_id = 87;
        let posts = vec![op, reply];
        let authors = std::collections::BTreeMap::from([
            (1, "rainkawa".to_owned()),
            (2, "rainkawa".to_owned()),
        ]);

        let html = thread_page((
            &board,
            &sample_thread(),
            &posts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &authors,
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(
            html.contains(
                r#"<a class="post-share-author" href="/u/rainkawa"><strong>@rainkawa</strong></a> paylaştı"#
            ),
            "a share must name the account behind the post and link to it: {html}"
        );
        assert!(
            html.contains(r#"class="post-share-link" href="/test/thread/87#p1">"#),
            "the permalink must be shown as text: {html}"
        );
        assert!(
            html.contains("post-share-op"),
            "the opening post carries the thread's share, so it is marked apart"
        );
    }

    #[test]
    /// A post that belongs to no account gets no share line at all. A share is
    /// a claim that a person passed this on, and there is no person to name
    /// behind a post written before accounts existed, posted without signing
    /// in, or posted anonymously — so an "anonymous share" would be a claim on
    /// the page that nobody on the page stands behind.
    fn a_post_belonging_to_no_account_is_shown_no_share() {
        let board = crate::test_fixtures::sample_board();
        let mut op = sample_post();
        op.is_op = true;
        op.thread_id = 87;
        let posts = vec![op];

        let html = thread_page((
            &board,
            &sample_thread(),
            &posts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));

        assert!(
            !html.contains("post-share"),
            "a post with no account behind it is shown no share control: {html}"
        );
        assert!(
            !html.contains("anonim"),
            "a share is never attributed to nobody in particular: {html}"
        );
    }

    #[test]
    /// The name typed into the form is free text, so a share is never read
    /// from it. A post whose name field spells out somebody else's account is
    /// shown no share at all when that post belongs to no account, and the
    /// account it does belong to is the one named — not the name in the field.
    fn a_typed_name_cannot_claim_a_share_in_another_account_name() {
        let board = crate::test_fixtures::sample_board();
        let mut op = sample_post();
        op.is_op = true;
        op.thread_id = 87;
        op.name = "Rainkawa".into();
        let posts = vec![op];

        let unlinked = thread_page((
            &board,
            &sample_thread(),
            &posts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));
        assert!(
            !unlinked.contains("paylaştı"),
            "a typed name must not produce a share in that name: {unlinked}"
        );

        let authors = std::collections::BTreeMap::from([(1, "baskasi".to_owned())]);
        let linked = thread_page((
            &board,
            &sample_thread(),
            &posts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &authors,
            "csrf",
            std::slice::from_ref(&board),
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            crate::templates::UserPreferences::default(),
            None,
            "",
        ));
        assert!(
            linked.contains("baskasi</strong></a> paylaştı"),
            "a share names the account behind the post, not the name in the form: {linked}"
        );
        assert!(
            !linked.contains("@Rainkawa</strong></a>"),
            "the typed name must not be linked as an account: {linked}"
        );
    }
}
