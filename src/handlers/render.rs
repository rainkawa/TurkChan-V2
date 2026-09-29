use crate::{
    db,
    error::{AppError, Result},
    handlers::posting,
    models::{Board, Pagination, PollData, Thread, ThreadSummary},
    templates,
    utils::crypto::hash_ip,
};
use sha2::{Digest as _, Sha256};

pub(super) struct BoardPageData {
    pub board: Board,
    pub pagination: Pagination,
    pub summaries: Vec<ThreadSummary>,
    pub is_admin: bool,
}

pub(super) struct ThreadPageData {
    pub board: Board,
    pub thread: Thread,
    pub posts: Vec<crate::models::Post>,
    pub poll: Option<PollData>,
    pub is_admin: bool,
    pub owned_post_controls: std::collections::BTreeMap<i64, templates::thread::OwnedPostControls>,
    pub votes: std::collections::BTreeMap<i64, db::PostVoteView>,
    /// Login name of the account behind each account-linked post, by post id.
    pub share_authors: std::collections::BTreeMap<i64, String>,
    /// The account behind each account-linked post, by post id.
    ///
    /// Kept beside the share names rather than folded into them because the
    /// header shows a role and an avatar, and neither can be read back out of a
    /// login name.
    pub author_profiles: std::collections::BTreeMap<i64, db::PostAuthorProfile>,
}

#[must_use]
pub(super) fn board_page_etag_signature(data: &BoardPageData) -> String {
    let mut hasher = Sha256::new();
    for summary in &data.summaries {
        update_thread_signature(&mut hasher, &summary.thread);
        update_sig_field(&mut hasher, &summary.omitted.to_string());
        for post in &summary.preview_posts {
            update_post_signature(&mut hasher, post);
        }
    }
    hex::encode(hasher.finalize())
}

/// The page's cache signature.
///
/// The scores are part of it because a vote re-renders the page the reader is
/// already on: a signature that ignored them would let the press be answered
/// with the page that was already cached, score unchanged, and the button would
/// look like it had done nothing.
#[must_use]
pub(super) fn thread_page_etag_signature(data: &ThreadPageData) -> String {
    let mut hasher = Sha256::new();
    update_thread_signature(&mut hasher, &data.thread);
    for post in &data.posts {
        update_post_signature(&mut hasher, post);
    }
    for (post_id, vote) in &data.votes {
        update_sig_field(&mut hasher, &post_id.to_string());
        update_sig_field(&mut hasher, &vote.score.to_string());
    }
    // A share is named after the account behind the post, so the name in it is
    // part of the page: a cached body has to stop answering once a post is
    // attributed to an account it was not attributed to before.
    for (post_id, username) in &data.share_authors {
        update_sig_field(&mut hasher, &post_id.to_string());
        update_sig_field(&mut hasher, username);
    }
    if let Some(poll) = &data.poll {
        update_poll_signature(&mut hasher, poll);
    }
    hex::encode(hasher.finalize())
}

fn update_sig_field(hasher: &mut Sha256, value: &str) {
    hasher.update(value.as_bytes());
    hasher.update([0]);
}

fn update_thread_signature(hasher: &mut Sha256, thread: &Thread) {
    update_sig_field(hasher, &thread.id.to_string());
    update_sig_field(hasher, &thread.bumped_at.to_string());
    update_sig_field(hasher, if thread.locked { "1" } else { "0" });
    update_sig_field(hasher, if thread.sticky { "1" } else { "0" });
    update_sig_field(hasher, if thread.archived { "1" } else { "0" });
    update_sig_field(hasher, &thread.reply_count.to_string());
    update_sig_field(hasher, thread.op_file.as_deref().unwrap_or(""));
    update_sig_field(hasher, thread.op_thumb.as_deref().unwrap_or(""));
}

fn update_post_signature(hasher: &mut Sha256, post: &crate::models::Post) {
    update_sig_field(hasher, &post.id.to_string());
    update_sig_field(hasher, &post.edited_at.unwrap_or(0).to_string());
    update_sig_field(hasher, post.file_path.as_deref().unwrap_or(""));
    update_sig_field(hasher, post.thumb_path.as_deref().unwrap_or(""));
    update_sig_field(hasher, post.mime_type.as_deref().unwrap_or(""));
    update_sig_field(hasher, post.audio_file_path.as_deref().unwrap_or(""));
    update_sig_field(hasher, post.audio_mime_type.as_deref().unwrap_or(""));
    update_sig_field(hasher, post.media_processing_state.as_deref().unwrap_or(""));
    update_sig_field(hasher, post.media_processing_error.as_deref().unwrap_or(""));
}

fn update_poll_signature(hasher: &mut Sha256, poll_data: &PollData) {
    update_sig_field(hasher, &poll_data.poll.id.to_string());
    update_sig_field(hasher, &poll_data.poll.thread_id.to_string());
    update_sig_field(hasher, &poll_data.poll.question);
    update_sig_field(hasher, &poll_data.poll.expires_at.to_string());
    update_sig_field(hasher, &poll_data.poll.created_at.to_string());
    update_sig_field(hasher, &poll_data.total_votes.to_string());
    update_sig_field(
        hasher,
        &poll_data.user_voted_option.unwrap_or_default().to_string(),
    );
    update_sig_field(hasher, if poll_data.is_expired { "1" } else { "0" });
    for option in &poll_data.options {
        update_sig_field(hasher, &option.id.to_string());
        update_sig_field(hasher, &option.poll_id.to_string());
        update_sig_field(hasher, &option.text);
        update_sig_field(hasher, &option.position.to_string());
        update_sig_field(hasher, &option.vote_count.to_string());
    }
}

pub(super) fn load_board_page_data(
    conn: &rusqlite::Connection,
    board_short: &str,
    page: i64,
    threads_per_page: i64,
    preview_replies: i64,
    admin_session_id: Option<&str>,
) -> Result<BoardPageData> {
    let is_admin = posting::is_admin_session(conn, admin_session_id);
    let board = db::get_board_by_short(conn, board_short)?
        .ok_or_else(|| AppError::NotFound(format!("Board /{board_short}/ bulunamadı")))?;
    let total = db::count_threads_for_board(conn, board.id)?;
    let pagination = Pagination::new(page, threads_per_page, total);
    let threads = db::get_threads_for_board(conn, board.id, threads_per_page, pagination.offset())?;
    let thread_ids = threads.iter().map(|thread| thread.id).collect::<Vec<_>>();
    let previews = db::get_preview_posts_for_threads(conn, &thread_ids, preview_replies)?;
    let summaries = threads
        .into_iter()
        .map(|thread| {
            let preview_posts = previews.get(&thread.id).cloned().unwrap_or_default();
            let omitted =
                (thread.reply_count - i64::try_from(preview_posts.len()).unwrap_or(0)).max(0);
            ThreadSummary {
                thread,
                preview_posts,
                omitted,
            }
        })
        .collect();
    Ok(BoardPageData {
        board,
        pagination,
        summaries,
        is_admin,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "the renderer accepts distinct request-scoped security, preference, and pagination inputs"
)]
pub(super) fn render_board_page(
    data: &BoardPageData,
    csrf_token: &str,
    admin_csrf_token: Option<&str>,
    error: Option<&str>,
    new_thread_prefill: Option<&templates::forms::PostFormState>,
    thread_badges: &std::collections::HashMap<i64, i64>,
    new_activity_enabled: bool,
    board_banner_html: &str,
    current_theme: Option<&str>,
    can_post: bool,
    user_preferences: templates::UserPreferences,
    account: Option<&templates::auth::AccountMenu>,
    account_menu_csrf: &str,
) -> String {
    let boards = templates::live_boards();
    templates::board_page(
        &data.board,
        &data.summaries,
        &data.pagination,
        csrf_token,
        boards.as_ref(),
        data.is_admin,
        admin_csrf_token,
        error,
        new_thread_prefill,
        thread_badges,
        new_activity_enabled,
        board_banner_html,
        current_theme,
        data.board.collapse_greentext,
        can_post,
        user_preferences,
        account,
        account_menu_csrf,
    )
}

pub(super) fn load_thread_page_data(
    conn: &rusqlite::Connection,
    board_short: &str,
    thread_id: i64,
    client_ip: &str,
    admin_session_id: Option<&str>,
    cookie_secret: &str,
    account_id: Option<i64>,
) -> Result<ThreadPageData> {
    let is_admin = posting::is_admin_session(conn, admin_session_id);
    let board = db::get_board_by_short(conn, board_short)?
        .ok_or_else(|| AppError::NotFound(format!("Board /{board_short}/ bulunamadı")))?;
    let thread = db::get_thread(conn, thread_id)?
        .ok_or_else(|| AppError::NotFound(format!("Thread {thread_id} not found")))?;
    if thread.board_id != board.id {
        return Err(AppError::NotFound("Konu bu board’da bulunamadı.".into()));
    }
    let posts = db::get_posts_for_thread(conn, thread_id)?;
    let ip_hash = hash_ip(client_ip, cookie_secret);
    let poll = db::get_poll_for_thread(conn, thread_id, &ip_hash)?;
    // Scores are public to every reader; only the reader's own pressed arrow
    // needs an account, so a page of posts costs the same two queries whatever
    // length it is and whether anyone is signed in or not.
    let post_ids = posts.iter().map(|post| post.id).collect::<Vec<_>>();
    let vote_map = db::post_vote_views(conn, &post_ids, account_id)?;
    let votes = post_ids
        .iter()
        .map(|id| (*id, vote_map.get(id).copied().unwrap_or_default()))
        .collect();
    // One query names every share on the page. It reads `posts.user_id` rather
    // than the name in the form, so a share belongs to the account that wrote
    // the post and cannot be claimed by typing somebody else's name.
    let share_authors = db::post_share_authors(conn, &post_ids)?
        .into_iter()
        .collect();
    // Read for the same reason and in the same pass as the share names: the
    // post's own name is free text, so the avatar and the role behind a post
    // can only come from the account that wrote it.
    let author_profiles = db::post_author_profiles(conn, &post_ids)?
        .into_iter()
        .collect();
    Ok(ThreadPageData {
        board,
        thread,
        posts,
        poll,
        is_admin,
        owned_post_controls: std::collections::BTreeMap::new(),
        votes,
        share_authors,
        author_profiles,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "the renderer accepts distinct request-scoped security, preference, and thread-state inputs"
)]
pub(super) fn render_thread_page(
    data: &ThreadPageData,
    csrf_token: &str,
    admin_csrf_token: Option<&str>,
    error: Option<&str>,
    success: Option<&str>,
    reply_prefill: Option<&templates::forms::PostFormState>,
    edit_overlay_state: Option<&templates::thread::EditOverlayState>,
    current_theme: Option<&str>,
    can_post: bool,
    user_preferences: templates::UserPreferences,
    account: Option<&templates::auth::AccountMenu>,
    account_menu_csrf: &str,
) -> String {
    let boards = templates::live_boards();
    templates::thread_page(
        &data.board,
        &data.thread,
        &data.posts,
        &data.owned_post_controls,
        &data.votes,
        &data.share_authors,
        &data.author_profiles,
        csrf_token,
        boards.as_ref(),
        data.is_admin,
        admin_csrf_token,
        data.poll.as_ref(),
        error,
        success,
        reply_prefill,
        edit_overlay_state,
        current_theme,
        data.board.collapse_greentext,
        can_post,
        user_preferences,
        account,
        account_menu_csrf,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        board_page_etag_signature, thread_page_etag_signature, BoardPageData, ThreadPageData,
    };
    use crate::db::PostVoteView;
    use crate::models::{
        Board, Pagination, Poll, PollData, PollOption, Post, Thread, ThreadSummary,
    };

    fn sample_board() -> Board {
        Board {
            id: 1,
            display_order: 0,
            short_name: "t".into(),
            max_archived_threads: 100,
            bump_limit: 300,
            allow_editing: true,
            edit_window_secs: 300,
            allow_video_embeds: true,
            show_poster_ids: true,
            ..crate::test_fixtures::sample_board()
        }
    }

    fn sample_thread(reply_count: i64) -> Thread {
        Thread {
            id: 42,
            board_id: 1,
            subject: Some("subject".into()),
            created_at: 100,
            bumped_at: 200,
            locked: false,
            sticky: false,
            archived: false,
            reply_count,
            image_count: 0,
            op_body: Some("op".into()),
            op_file: None,
            op_thumb: None,
            op_name: Some("anon".into()),
            op_tripcode: None,
            op_media_width: None,
            op_media_height: None,
            op_id: Some(1),
        }
    }

    fn sample_post(id: i64) -> Post {
        Post {
            id,
            thread_id: 42,
            board_id: 1,
            name: "Anonymous".into(),
            tripcode: None,
            subject: None,
            body: format!("post {id}"),
            body_html: format!("post {id}"),
            ip_hash: Some("hash".into()),
            file_path: None,
            file_name: None,
            file_size: None,
            thumb_path: None,
            mime_type: None,
            media_type: None,
            audio_file_path: None,
            audio_file_name: None,
            audio_file_size: None,
            audio_mime_type: None,
            created_at: 100 + id,
            deletion_token: "token".into(),
            is_op: id == 1,
            edited_at: None,
            media_processing_state: None,
            media_processing_error: None,
            user_id: None,
        }
    }

    fn sample_poll_data(user_voted_option: Option<i64>, vote_counts: [i64; 2]) -> PollData {
        PollData {
            poll: Poll {
                id: 7,
                thread_id: 42,
                question: "poll?".into(),
                expires_at: 2000,
                created_at: 100,
            },
            options: vec![
                PollOption {
                    id: 11,
                    poll_id: 7,
                    text: "yes".into(),
                    position: 0,
                    vote_count: vote_counts[0],
                },
                PollOption {
                    id: 12,
                    poll_id: 7,
                    text: "no".into(),
                    position: 1,
                    vote_count: vote_counts[1],
                },
            ],
            total_votes: vote_counts[0] + vote_counts[1],
            user_voted_option,
            is_expired: false,
        }
    }

    #[test]
    fn thread_page_etag_changes_when_reply_is_removed() {
        let board = sample_board();
        let before = ThreadPageData {
            board: board.clone(),
            thread: sample_thread(2),
            posts: vec![sample_post(1), sample_post(2), sample_post(3)],
            poll: None,
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: Default::default(),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };
        let after = ThreadPageData {
            board,
            thread: sample_thread(1),
            posts: vec![sample_post(1), sample_post(3)],
            poll: None,
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: Default::default(),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };

        assert_ne!(
            thread_page_etag_signature(&before),
            thread_page_etag_signature(&after)
        );
    }

    #[test]
    fn thread_page_etag_changes_when_media_processing_state_changes() {
        let board = sample_board();
        let mut pending_post = sample_post(2);
        pending_post.file_path = Some("test/clip.mp4".into());
        pending_post.thumb_path = Some("test/thumbs/clip.webp".into());
        pending_post.mime_type = Some("video/mp4".into());
        pending_post.media_processing_state = Some("pending".into());

        let before = ThreadPageData {
            board: board.clone(),
            thread: sample_thread(1),
            posts: vec![sample_post(1), pending_post.clone()],
            poll: None,
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: Default::default(),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };

        pending_post.file_path = Some("test/clip.webm".into());
        pending_post.mime_type = Some("video/webm".into());
        pending_post.media_processing_state = None;

        let after = ThreadPageData {
            board,
            thread: sample_thread(1),
            posts: vec![sample_post(1), pending_post],
            poll: None,
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: Default::default(),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };

        assert_ne!(
            thread_page_etag_signature(&before),
            thread_page_etag_signature(&after)
        );
    }

    #[test]
    fn thread_page_etag_changes_when_poll_vote_count_changes() {
        let board = sample_board();
        let before = ThreadPageData {
            board: board.clone(),
            thread: sample_thread(0),
            posts: vec![sample_post(1)],
            poll: Some(sample_poll_data(None, [0, 0])),
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: Default::default(),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };
        let after = ThreadPageData {
            board,
            thread: sample_thread(0),
            posts: vec![sample_post(1)],
            poll: Some(sample_poll_data(Some(11), [1, 0])),
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: Default::default(),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };

        assert_ne!(
            thread_page_etag_signature(&before),
            thread_page_etag_signature(&after)
        );
    }

    #[test]
    fn thread_page_etag_changes_when_poll_viewer_vote_state_changes() {
        let board = sample_board();
        let before = ThreadPageData {
            board: board.clone(),
            thread: sample_thread(0),
            posts: vec![sample_post(1)],
            poll: Some(sample_poll_data(None, [1, 0])),
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: Default::default(),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };
        let after = ThreadPageData {
            board,
            thread: sample_thread(0),
            posts: vec![sample_post(1)],
            poll: Some(sample_poll_data(Some(11), [1, 0])),
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: Default::default(),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };

        assert_ne!(
            thread_page_etag_signature(&before),
            thread_page_etag_signature(&after)
        );
    }

    #[test]
    fn board_page_etag_changes_when_reply_preview_changes() {
        let board = sample_board();
        let before = BoardPageData {
            board: board.clone(),
            pagination: Pagination::new(1, 10, 1),
            summaries: vec![ThreadSummary {
                thread: sample_thread(2),
                preview_posts: vec![sample_post(2), sample_post(3)],
                omitted: 0,
            }],
            is_admin: false,
        };
        let after = BoardPageData {
            board,
            pagination: Pagination::new(1, 10, 1),
            summaries: vec![ThreadSummary {
                thread: sample_thread(1),
                preview_posts: vec![sample_post(3)],
                omitted: 0,
            }],
            is_admin: false,
        };

        assert_ne!(
            board_page_etag_signature(&before),
            board_page_etag_signature(&after)
        );
    }

    #[test]
    fn board_page_etag_changes_when_op_media_changes() {
        let board = sample_board();
        let mut before_thread = sample_thread(0);
        before_thread.op_file = Some("test/op.mp4".into());
        before_thread.op_thumb = Some("test/thumbs/op.webp".into());

        let mut after_thread = before_thread.clone();
        after_thread.op_file = Some("test/op.webm".into());

        let before = BoardPageData {
            board: board.clone(),
            pagination: Pagination::new(1, 10, 1),
            summaries: vec![ThreadSummary {
                thread: before_thread,
                preview_posts: Vec::new(),
                omitted: 0,
            }],
            is_admin: false,
        };
        let after = BoardPageData {
            board,
            pagination: Pagination::new(1, 10, 1),
            summaries: vec![ThreadSummary {
                thread: after_thread,
                preview_posts: Vec::new(),
                omitted: 0,
            }],
            is_admin: false,
        };

        assert_ne!(
            board_page_etag_signature(&before),
            board_page_etag_signature(&after)
        );
    }

    #[test]
    /// A vote re-renders the page the reader is standing on, so the score has
    /// to be part of the page's signature. A signature that ignored it would let
    /// the press be answered with the page that was already cached, and the
    /// button would appear to have done nothing.
    fn thread_page_etag_changes_when_a_post_score_changes() {
        let board = sample_board();
        let before = ThreadPageData {
            board: board.clone(),
            thread: sample_thread(1),
            posts: vec![sample_post(1)],
            poll: None,
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: std::collections::BTreeMap::from([(1, PostVoteView::default())]),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };
        let after = ThreadPageData {
            board,
            thread: sample_thread(1),
            posts: vec![sample_post(1)],
            poll: None,
            is_admin: false,
            owned_post_controls: std::collections::BTreeMap::new(),
            votes: std::collections::BTreeMap::from([(
                1,
                PostVoteView {
                    score: 1,
                    my_vote: 1,
                },
            )]),
            share_authors: Default::default(),
            author_profiles: Default::default(),
        };

        assert_ne!(
            thread_page_etag_signature(&before),
            thread_page_etag_signature(&after),
            "a changed score must produce a changed page signature"
        );
    }
}
