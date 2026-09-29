//! HTML form fragments injected into board and thread pages.
//!
//! These are not full pages: they produce `<div>` snippets that board and
//! thread templates embed inside their layouts.

use crate::config::CONFIG;
use crate::models::Board;
use crate::utils::sanitize::escape_html;

/// User-entered fields preserved when a post form must be rendered again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PostFormState {
    /// Poster name field.
    pub name: String,
    /// Thread subject field.
    pub subject: String,
    /// Post body field.
    pub body: String,
    /// Whether the reply should avoid bumping its thread.
    pub sage: bool,
    /// Whether the submission is published under a chosen name instead of the
    /// account's own.
    pub anonymous: bool,
}

/// Upload capabilities needed to choose the form's media controls.
struct UploadFormPolicy {
    /// Whether the board accepts at least one upload type.
    uploads_enabled: bool,
}

/// Choose the name a posting form starts with.
///
/// A re-render after a rejected submission keeps whatever the account typed,
/// because that text is the one thing the server must not silently replace. A
/// fresh form starts from the signed-in account's own name, so a post is not
/// published as "Anonymous" merely because the name box was left empty, and a
/// visitor without an account still gets an empty box to fill in.
fn prefill_name(prefill: Option<&PostFormState>, poster_name: &str) -> String {
    match prefill {
        Some(state) => state.name.clone(),
        None => poster_name.to_owned(),
    }
}

/// Creates the opaque token used to reject duplicate form submissions.
fn new_submission_token() -> String {
    crate::utils::crypto::random_hex(16)
}

/// Renders the initially hidden upload progress row.
const fn upload_progress_row() -> &'static str {
    r#"    <tr class="upload-progress-row" hidden>
        <td>yükleme</td>
        <td>
          <div class="compress-progress upload-progress-wrap" style="display:block;margin:0">
            <div class="compress-progress-track"><div class="compress-progress-bar upload-progress-bar" style="width:0%"></div></div>
            <div class="compress-progress-text upload-progress-text">Yükleme hazırlanıyor…</div>
          </div>
        </td></tr>"#
}

/// MIME types and extensions accepted by the audio input.
const AUDIO_ACCEPT: &str =
    "audio/mpeg,audio/mp3,audio/ogg,application/ogg,audio/oga,audio/opus,audio/flac,audio/x-flac,audio/wav,audio/wave,audio/x-wav,audio/vnd.wave,audio/mp4,audio/m4a,audio/x-m4a,audio/aac,audio/x-aac,audio/webm,.mp3,.ogg,.oga,.opus,.flac,.wav,.m4a,.aac,.webm";
/// MIME types and extensions accepted by the video input.
const VIDEO_ACCEPT: &str = "video/mp4,video/webm,video/x-matroska,video/matroska,.mp4,.webm,.mkv";
/// MIME types and extensions accepted by the image input.
const IMAGE_ACCEPT: &str = "image/jpeg,image/png,image/gif,image/webp,image/avif,image/heic,image/heif,.avif,.heic,.heif";
/// Maximum number of characters in a poll option.
const POLL_OPTION_MAX_LENGTH: usize = 200;
/// Maximum number of options in a poll.
const POLL_OPTION_MAX_COUNT: usize = 20;

/// Derives upload-control visibility from the board configuration.
fn build_upload_form_policy(board: &Board) -> UploadFormPolicy {
    let allow_any_files = CONFIG.enable_any_file_uploads_feature && board.allow_any_files;

    let uploads_enabled = board.allow_images
        || board.allow_audio
        || board.allow_video
        || board.allow_pdf
        || allow_any_files;

    UploadFormPolicy { uploads_enabled }
}

/// Wraps explanatory copy in the standard form-help element.
fn form_hint(text: &str) -> String {
    format!(r#"<span class="form-field-help">{text}</span>"#)
}

/// Renders the row shown when all upload types are disabled.
const fn render_uploads_disabled_row() -> &'static str {
    r#"    <tr><td>yüklemeler</td>
        <td><span class="post-form-mobile-label">Yüklemeler</span><span class="form-field-help">bu board’da yüklemeler kapalı</span></td></tr>"#
}

/// Renders a CAPTCHA challenge row with board-specific element identifiers.
fn render_captcha_row(board_short: &str, reply_suffix: &str, refresh_href: &str) -> String {
    let captcha_id = crate::captcha::new_captcha_id();
    let board = escape_html(board_short);
    let image_src = format!("/captcha/{captcha_id}?board={board}");
    let answer_id = format!("captcha-answer-{board}{reply_suffix}");
    let (refresh_path, fragment) = refresh_href
        .split_once('#')
        .map_or((refresh_href, None), |(path, fragment)| {
            (path, Some(fragment))
        });
    let query_separator = if refresh_path.contains('?') { '&' } else { '?' };
    let refresh_href = format!(
        "{refresh_path}{query_separator}captcha_refresh={captcha_id}{}",
        fragment.map_or_else(String::new, |value| format!("#{value}"))
    );
    format!(
        r#"    <tr id="captcha-row-{board}{suffix}"><td><label for="{answer_id}">captcha</label></td>
        <td>
          <label class="post-form-mobile-label" for="{answer_id}">Captcha</label>
          <div class="captcha-challenge">
            <img class="captcha-image" src="{image_src}" alt="CAPTCHA doğrulama görseli" width="220" height="120">
            <a class="form-field-help captcha-refresh-link" href="{refresh_href}">yeni doğrulama</a>
          </div>
          <input type="hidden" name="captcha_id" value="{captcha_id}">
          <input type="text" id="{answer_id}" name="captcha_answer" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="16" required>
          <span class="form-field-help">Görselde gösterilen metni girin. Süresi dolarsa veya hatalı olursa yeni bir doğrulama isteyin.</span>
        </td></tr>"#,
        board = board,
        suffix = reply_suffix,
        answer_id = escape_html(&answer_id),
        image_src = escape_html(&image_src),
        captcha_id = escape_html(&captcha_id),
        refresh_href = escape_html(&refresh_href),
    )
}

/// Renders one numbered poll-option input row.
fn render_poll_option_row(option_number: usize) -> String {
    format!(
        r#"<div class="poll-option-row"><input type="text" class="poll-option-input" name="poll_option" aria-label="{option_number}. anket seçeneği" placeholder="Seçenek {option_number}" maxlength="{POLL_OPTION_MAX_LENGTH}"><button type="button" class="poll-remove-btn" data-action="remove-poll-option" aria-label="Anket seçeneğini kaldır" hidden>✕</button></div>"#
    )
}

/// Image, video, audio, PDF, and generic upload limits in mebibytes.
type UploadSizeLimitsMb = (usize, usize, usize, usize, usize);

/// Converts a board's byte limits to the mebibyte values displayed by forms.
fn upload_size_limits_mb(board: &Board) -> UploadSizeLimitsMb {
    (
        board.max_image_size_bytes() / 1024 / 1024,
        board.max_video_size_bytes() / 1024 / 1024,
        board.max_audio_size_bytes() / 1024 / 1024,
        board.max_pdf_size_bytes() / 1024 / 1024,
        board.max_generic_upload_size_bytes() / 1024 / 1024,
    )
}

/// Builds the `accept` value and explanatory copy for a combined file input.
fn single_upload_accept_and_hint(
    board: &Board,
    allow_any_files: bool,
    limits: UploadSizeLimitsMb,
) -> (String, String) {
    let (image_mb, video_mb, audio_mb, pdf_mb, generic_upload_mb) = limits;
    let mut accept_parts: Vec<&str> = Vec::new();
    let mut hint_parts: Vec<String> = Vec::new();

    if board.allow_images {
        accept_parts.push(IMAGE_ACCEPT);
        hint_parts.push(format!("jpg/png/gif/webp/avif/heic · en fazla {image_mb} MiB"));
    }
    if board.allow_video {
        accept_parts.push(VIDEO_ACCEPT);
        hint_parts.push(format!("mp4/webm/mkv · en fazla {video_mb} MiB"));
    }
    if board.allow_audio {
        accept_parts.push(AUDIO_ACCEPT);
        hint_parts.push(format!(
            "mp3/ogg/oga/opus/flac/wav/m4a/aac/webm · en fazla {audio_mb} MiB"
        ));
    }
    if board.allow_pdf {
        accept_parts.push("application/pdf,.pdf");
        hint_parts.push(format!("pdf · en fazla {pdf_mb} MiB"));
    }
    match (board.allow_images, board.allow_video) {
        (true, true) => hint_parts.push("büyük resimler/videolar otomatik sıkıştırılabilir".to_owned()),
        (true, false) => hint_parts.push("büyük resimler otomatik sıkıştırılabilir".to_owned()),
        (false, true) => hint_parts.push("büyük videolar otomatik sıkıştırılabilir".to_owned()),
        (false, false) => {}
    }

    let file_accept = if allow_any_files {
        String::new()
    } else {
        accept_parts.join(",")
    };
    let file_hint = if allow_any_files && hint_parts.is_empty() {
        format!("diğer dosyalar eklenti olarak güvenle indirilir · en fazla {generic_upload_mb} MiB")
    } else if allow_any_files {
        format!(
            "{} &nbsp;|&nbsp; diğer dosyalar eklenti olarak güvenle indirilir",
            hint_parts.join(" &nbsp;|&nbsp; ")
        )
    } else {
        hint_parts.join(" &nbsp;|&nbsp; ")
    };
    (file_accept, file_hint)
}

/// Renders the upload controls used when one primary file input is sufficient.
fn render_single_upload_row(board: &Board, audio_image_hint: &str) -> String {
    let limits = upload_size_limits_mb(board);
    let (image_mb, _, audio_mb, _, _) = limits;
    let allow_any_files = CONFIG.enable_any_file_uploads_feature && board.allow_any_files;
    let audio_image_dual_mode = board.allow_audio
        && board.allow_images
        && !board.allow_video
        && !board.allow_pdf
        && !allow_any_files;
    let (file_accept, file_hint) = single_upload_accept_and_hint(board, allow_any_files, limits);

    let optional_image_row = if audio_image_dual_mode {
        format!(
            r#"<details class="upload-secondary-toggle">
              <summary aria-label="İsteğe bağlı resim yüklemesini göster">▾ İsteğe Bağlı Resim</summary>
              <div class="upload-secondary-panel">
                <label class="upload-secondary-label" for="post-form-image-file">isteğe bağlı resim</label>
                <input type="file" id="post-form-image-file" name="image_file" data-onchange-check-size="1" accept="{IMAGE_ACCEPT}">
                <span class="form-field-help">{audio_image_hint} · jpg/png/gif/webp/avif/heic · en fazla {image_mb} MiB · büyük resimler otomatik sıkıştırılabilir</span>
              </div>
            </details>"#
        )
    } else {
        String::new()
    };

    let primary_name = if audio_image_dual_mode {
        "audio_file"
    } else {
        "file"
    };
    let primary_label = if primary_name == "audio_file" {
        "ses"
    } else {
        "yükleme"
    };
    let primary_id = if primary_name == "audio_file" {
        "post-form-audio-file"
    } else {
        "post-form-file"
    };
    let primary_accept = if audio_image_dual_mode {
        AUDIO_ACCEPT.to_owned()
    } else {
        file_accept
    };
    let primary_hint = if audio_image_dual_mode {
        format!("mp3/ogg/oga/opus/flac/wav/m4a/aac/webm · en fazla {audio_mb} MiB")
    } else {
        file_hint
    };

    let mobile_label = if primary_name == "audio_file" {
        "Ses"
    } else {
        "Yükleme"
    };

    format!(
        r#"    <tr><td><label for="{primary_id}">{primary_label}</label></td>
        <td><label class="post-form-mobile-label" for="{primary_id}">{mobile_label}</label><input type="file" id="{primary_id}" name="{primary_name}" data-onchange-check-size="1" accept="{primary_accept}">
            {primary_hint_html}
            {optional_image_row}</td></tr>"#,
        primary_id = primary_id,
        mobile_label = mobile_label,
        primary_hint_html = form_hint(&primary_hint),
    )
}

/// New-thread submission form. Embedded on board index and catalog pages.
pub(super) fn new_thread_form(
    board_short: &str,
    csrf_token: &str,
    board: &Board,
    prefill: Option<&PostFormState>,
    poster_name: &str,
    refresh_href: &str,
) -> String {
    let submission_token = new_submission_token();
    let upload_policy = build_upload_form_policy(board);
    let upload_row = if upload_policy.uploads_enabled {
        render_single_upload_row(board, "ses gönderisi için isteğe bağlı kapak resmi")
    } else {
        String::new()
    };

    let uploads_disabled_row = if upload_policy.uploads_enabled {
        String::new()
    } else {
        render_uploads_disabled_row().to_owned()
    };

    let captcha_row = if board.allow_captcha {
        render_captcha_row(board_short, "", refresh_href)
    } else {
        String::new()
    };

    let poll_option_rows = [render_poll_option_row(1), render_poll_option_row(2)].concat();
    let extra_poll_option_rows: String = (3..=POLL_OPTION_MAX_COUNT)
        .map(render_poll_option_row)
        .collect();
    let name_value = prefill_name(prefill, poster_name);
    let anon_checked = if prefill.is_some_and(|state| state.anonymous) {
        " checked"
    } else {
        ""
    };
    let subject_value = prefill.map_or("", |state| state.subject.as_str());
    let body_value = prefill.map_or("", |state| state.body.as_str());

    format!(
        r#"<div class="post-form-container">
<div class="post-form-title">[ yeni konu ]</div>
<form class="post-form" method="POST" action="/{board}" enctype="multipart/form-data">
  <input type="hidden" name="_csrf" value="{csrf}">
  <input type="hidden" name="submission_token" value="{submission_token}">
  <table>
    <tr><td><label for="thread-name">ad</label></td>
        <td><label class="post-form-mobile-label" for="thread-name">Ad</label><input type="text" id="thread-name" name="name" value="{name_value}" placeholder="Anonim" maxlength="64">
            <span class="tripcode-hint" title="Adın sonuna #gizli yazarsan görünen bir tripcode oluşur, ##gizli yazarsan parolan gösterilmez.">#gizli &#183; ##gizli</span>
            <label class="anon-label" title="&#304;aretlenirse g&#246;nderi hesab&#305;na ba&#287;lanmaz ve ad alan&#305;nda yaz&#305;lan isimle payla&#351;&#305;l&#305;r."><input type="checkbox" name="anonymous" value="1"{anon_checked}> anonim payla&#351;</label></td></tr>
    <tr><td><label for="thread-subject">konu</label></td>
        <td><label class="post-form-mobile-label" for="thread-subject">Konu</label><input type="text" id="thread-subject" name="subject" value="{subject_value}" maxlength="128">
            <button type="submit">konuyu gönder</button></td></tr>
    <tr><td><label for="thread-body">gövde</label></td>
        <td><label class="post-form-mobile-label" for="thread-body">Gövde</label><textarea id="thread-body" name="body" rows="5" maxlength="4096">{body_value}</textarea>
            <div class="markup-hint">
              <span title="Greentext">&#62;green</span>
              <span title="Kalın">**kalın**</span>
              <span title="İtalik">__italik__</span>
              <span title="Spoiler">[spoiler]text[/spoiler]</span>
              <span title="Yanıt">&gt;&gt;123</span>
              <span title="Boardlar arası">&gt;&gt;&gt;/b/123</span>
              <span title="Emoji">:fire:</span>
            </div>
        </td></tr>
    {uploads_disabled_row}
    {upload_row}
    {upload_progress_row}
    {captcha_row}
    <tr class="poll-row">
        <td colspan="2">
        <span class="post-form-mobile-label">Anket</span>
        <details class="poll-creator">
          <summary>[ 📊 Bu konuya anket ekle ]</summary>
          <div class="poll-creator-inner">
            <div class="poll-creator-row">
              <label>Soru<input type="text" name="poll_question" placeholder="Ne düşünüyorsun?" maxlength="500"></label>
            </div>
            <div id="poll-options-list" data-poll-option-maxlength="{poll_option_max_length}" data-poll-option-maxcount="{poll_option_max_count}">
              {poll_option_rows}
              <noscript><details><summary>Daha fazla anket seçeneği</summary>{extra_poll_option_rows}</details></noscript>
            </div>
            <button type="button" class="poll-add-btn" data-action="add-poll-option">+ Seçenek Ekle</button>
            <div class="poll-creator-row poll-duration-row">
              <label>Süre
                <input type="number" name="poll_duration_value" value="24" min="1" max="720" class="poll-duration-input">
                <select name="poll_duration_unit" class="poll-duration-unit">
                  <option value="hours">Saat</option>
                  <option value="minutes">Dakika</option>
                  <option value="days">Gün</option>
                </select>
              </label>
            </div>
          </div>
        </details>
        </td></tr>
  </table>
</form>
</div>
"#,
        board = escape_html(board_short),
        csrf = escape_html(csrf_token),
        submission_token = escape_html(&submission_token),
        name_value = escape_html(&name_value),
        anon_checked = anon_checked,
        subject_value = escape_html(subject_value),
        body_value = escape_html(body_value),
        uploads_disabled_row = uploads_disabled_row,
        upload_row = upload_row,
        upload_progress_row = upload_progress_row(),
        captcha_row = captcha_row,
        poll_option_max_length = POLL_OPTION_MAX_LENGTH,
        poll_option_max_count = POLL_OPTION_MAX_COUNT,
        poll_option_rows = poll_option_rows,
    )
}

/// Reply form injected into thread pages.
pub(super) fn reply_form(
    board_short: &str,
    thread_id: i64,
    csrf_token: &str,
    board: &Board,
    prefill: Option<&PostFormState>,
    poster_name: &str,
) -> String {
    let submission_token = new_submission_token();
    let upload_policy = build_upload_form_policy(board);
    let upload_row = if upload_policy.uploads_enabled {
        render_single_upload_row(board, "ses yanıtı için isteğe bağlı kapak resmi")
    } else {
        String::new()
    };

    let uploads_disabled_row = if upload_policy.uploads_enabled {
        String::new()
    } else {
        render_uploads_disabled_row().to_owned()
    };

    let captcha_row = if board.allow_captcha {
        render_captcha_row(
            board_short,
            "-reply",
            &format!("/{board_short}/thread/{thread_id}#post-form-wrap"),
        )
    } else {
        String::new()
    };
    let name_value = prefill_name(prefill, poster_name);
    let anon_checked = if prefill.is_some_and(|state| state.anonymous) {
        " checked"
    } else {
        ""
    };
    let body_value = prefill.map_or("", |state| state.body.as_str());
    let sage_checked = if prefill.is_some_and(|state| state.sage) {
        " checked"
    } else {
        ""
    };

    format!(
        r#"<div class="post-form-container reply-form-container">
<div class="post-form-title">[ konuya yanıt ]</div>
<form class="post-form" method="POST" action="/{board}/thread/{tid}" enctype="multipart/form-data">
  <input type="hidden" name="_csrf" value="{csrf}">
  <input type="hidden" name="submission_token" value="{submission_token}">
  <table>
    <tr><td><label for="reply-name">ad</label></td>
        <td><label class="post-form-mobile-label" for="reply-name">Ad</label><input type="text" id="reply-name" name="name" value="{name_value}" placeholder="Anonim" maxlength="64">
            <span class="tripcode-hint" title="Adın sonuna #gizli yazarsan görünen bir tripcode oluşur, ##gizli yazarsan parolan gösterilmez.">#gizli &#183; ##gizli</span>
            <label class="anon-label" title="&#304;aretlenirse g&#246;nderi hesab&#305;na ba&#287;lanmaz ve ad alan&#305;nda yaz&#305;lan isimle payla&#351;&#305;l&#305;r."><input type="checkbox" name="anonymous" value="1"{anon_checked}> anonim payla&#351;</label></td></tr>
    <tr><td><label for="reply-body">gövde</label></td>
        <td><label class="post-form-mobile-label" for="reply-body">Gövde</label><textarea id="reply-body" name="body" rows="4" maxlength="4096">{body_value}</textarea>
            <button type="submit">yanıtı gönder</button></td></tr>
    {uploads_disabled_row}
    {upload_row}
    {upload_progress_row}
    <tr><td>seçenekler</td>
        <td><span class="post-form-mobile-label">Seçenekler</span><label class="sage-label"><input type="checkbox" name="sage" value="1"{sage_checked}> sage <span class="sage-hint">(konuyu yukarı taşıma)</span></label></td></tr>
    {captcha_row}
  </table>
</form>
</div>"#,
        board = escape_html(board_short),
        tid = thread_id,
        csrf = escape_html(csrf_token),
        submission_token = escape_html(&submission_token),
        name_value = escape_html(&name_value),
        anon_checked = anon_checked,
        body_value = escape_html(body_value),
        sage_checked = sage_checked,
        uploads_disabled_row = uploads_disabled_row,
        upload_row = upload_row,
        upload_progress_row = upload_progress_row(),
        captcha_row = captcha_row,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        build_upload_form_policy, new_thread_form, render_captcha_row, render_poll_option_row,
        reply_form, PostFormState, AUDIO_ACCEPT, POLL_OPTION_MAX_COUNT, POLL_OPTION_MAX_LENGTH,
    };
    use anyhow::Result;

    fn uploads_disabled_board() -> crate::models::Board {
        crate::models::Board {
            allow_images: false,
            allow_video: false,
            allow_audio: false,
            ..crate::test_fixtures::sample_board()
        }
    }

    fn audio_image_board() -> crate::models::Board {
        crate::models::Board {
            allow_images: true,
            allow_audio: true,
            ..uploads_disabled_board()
        }
    }

    #[test]
    fn upload_policy_marks_disabled_board_as_non_uploadable() {
        let policy = build_upload_form_policy(&uploads_disabled_board());
        assert!(!policy.uploads_enabled);
    }

    #[test]
    fn new_thread_form_hides_file_input_when_uploads_disabled() {
        let html = new_thread_form("test", "csrf", &uploads_disabled_board(), None, "Rain", "/test");
        assert!(!html.contains("type=\"file\" name=\"file\""));
        assert!(!html.contains("name=\"image_file\""));
        assert!(!html.contains("name=\"audio_file\""));
        assert!(html.contains("bu board’da yüklemeler kapalı"));
    }

    #[test]
    fn reply_form_hides_file_input_when_uploads_disabled() {
        let html = reply_form("test", 42, "csrf", &uploads_disabled_board(), None, "Rain");
        assert!(!html.contains("type=\"file\" name=\"file\""));
        assert!(!html.contains("name=\"image_file\""));
        assert!(!html.contains("name=\"audio_file\""));
        assert!(html.contains("bu board’da yüklemeler kapalı"));
    }

    #[test]
    fn audio_image_form_is_audio_first_and_cover_image_second() {
        let html = new_thread_form("test", "csrf", &audio_image_board(), None, "/test");
        let audio_pos = html.find("name=\"audio_file\"");
        let image_pos = html.find("name=\"image_file\"");
        assert!(audio_pos.is_some(), "audio row should be present");
        assert!(image_pos.is_some(), "image row should be present");
        assert!(audio_pos < image_pos);
        assert!(html.contains(r#"<td><label for="post-form-audio-file">ses</label></td>"#));
        assert!(html.contains("İsteğe Bağlı Resim"));
        assert!(html.contains("ses gönderisi için isteğe bağlı kapak resmi"));
        assert!(html.contains("image/heic"));
        assert!(html.contains(".heic"));
        assert!(html.contains(&format!("accept=\"{AUDIO_ACCEPT}\"")));
        assert!(html.contains("mp3/ogg/oga/opus/flac/wav/m4a/aac/webm · en fazla"));
        assert!(
            !html.contains(
                "jpg/png/gif/webp/heic · en fazla 8 MiB &nbsp;|&nbsp; mp3/ogg/oga/opus/flac/wav/m4a/aac/webm"
            )
        );
        assert!(!html.contains("video/mp4,video/webm"));
        assert!(!html.contains("name=\"file\""));
    }

    #[test]
    fn mixed_media_form_uses_single_upload_input() {
        let html = new_thread_form(
            "test",
            "csrf",
            &crate::models::Board {
                allow_images: true,
                allow_video: true,
                allow_audio: true,
                ..uploads_disabled_board()
            },
            None,
            "Rain",
            "/test",
        );
        assert!(html.contains("<td>yükleme</td>"));
        assert!(html.contains("name=\"file\""));
        assert!(!html.contains("name=\"audio_file\""));
        assert!(!html.contains("name=\"image_file\""));
    }

    #[test]
    fn post_forms_include_submission_token() {
        let board = uploads_disabled_board();
        let thread_html = new_thread_form("test", "csrf", &board, None, "Rain", "/test");
        let reply_html = reply_form("test", 42, "csrf", &board, None, "Rain");

        assert!(thread_html.contains("name=\"submission_token\""));
        assert!(reply_html.contains("name=\"submission_token\""));
    }

    #[test]
    fn poll_option_rows_share_the_same_max_length() {
        let initial_row = render_poll_option_row(1);
        assert!(initial_row.contains(&format!(r#"maxlength="{POLL_OPTION_MAX_LENGTH}""#)));

        let html = new_thread_form("test", "csrf", &uploads_disabled_board(), None, "Rain", "/test");
        assert!(html.contains(&format!(
            r#"data-poll-option-maxlength="{POLL_OPTION_MAX_LENGTH}""#
        )));
        assert!(html.contains(&format!(
            r#"data-poll-option-maxcount="{POLL_OPTION_MAX_COUNT}""#
        )));
        assert_eq!(
            html.matches(r#"class="poll-option-input""#).count(),
            POLL_OPTION_MAX_COUNT
        );
    }

    #[test]
    fn poll_creator_is_wrapped_in_a_valid_table_row() {
        let html = new_thread_form("test", "csrf", &uploads_disabled_board(), None, "Rain", "/test");

        assert!(html.contains(
            r#"<tr class="poll-row">
        <td colspan="2">
        <span class="post-form-mobile-label">Anket</span>"#,
        ));
    }

    #[test]
    fn post_forms_preserve_submitted_text_state() {
        let board = crate::models::Board {
            allow_editing: true,
            ..uploads_disabled_board()
        };
        let state = PostFormState {
            name: "anon".into(),
            subject: "subject".into(),
            body: "draft body".into(),
            sage: true,
            anonymous: true,
        };
        let thread_html = new_thread_form("test", "csrf", &board, Some(&state), "Rain", "/test");
        let reply_html = reply_form("test", 42, "csrf", &board, Some(&state), "Rain");

        assert!(thread_html.contains(r#"<label for="thread-name">ad</label>"#));
        assert!(thread_html.contains(r#"id="thread-name" name="name" value="anon""#));
        assert!(thread_html.contains(r#"<label for="thread-subject">konu</label>"#));
        assert!(thread_html.contains(r#"id="thread-subject" name="subject" value="subject""#));
        assert!(thread_html.contains(">draft body</textarea>"));
        assert!(!thread_html.contains(r#"name="deletion_token""#));

        assert!(reply_html.contains(r#"<label for="reply-name">ad</label>"#));
        assert!(reply_html.contains(r#"id="reply-name" name="name" value="anon""#));
        assert!(reply_html.contains(">draft body</textarea>"));
        assert!(!reply_html.contains(r#"name="deletion_token""#));
        assert!(reply_html.contains(r#"name="sage" value="1" checked"#));
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    fn a_posting_form_starts_from_the_signed_in_account_name() -> Result<()> {
        let board = crate::models::Board {
            allow_editing: true,
            ..uploads_disabled_board()
        };

        let thread_html = new_thread_form("test", "csrf", &board, None, "Rain", "/test");
        let reply_html = reply_form("test", 42, "csrf", &board, None, "Rain");
        for html in [&thread_html, &reply_html] {
            assert!(
                html.contains(r#"name="name" value="Rain""#),
                "a form must not start as Anonymous when the account has a name"
            );
            assert!(
                html.contains(r#"<input type="checkbox" name="anonymous" value="1">"#),
                "the tick that publishes a post under a chosen name must be offered"
            );
        }

        // A visitor without an account has no name to start from, and the form
        // is not invented one on their behalf.
        let guest = new_thread_form("test", "csrf", &board, None, "", "/test");
        assert!(
            guest.contains(r#"name="name" value="""#),
            "a visitor with no account must still be asked for a name"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally panic on failure"
    )]
    fn the_anonymous_tick_survives_a_rejected_submission() -> Result<()> {
        let board = crate::models::Board {
            allow_editing: true,
            ..uploads_disabled_board()
        };
        let state = PostFormState {
            name: "seçilen isim".into(),
            body: "gövde".into(),
            anonymous: true,
            ..PostFormState::default()
        };

        let thread_html = new_thread_form("test", "csrf", &board, Some(&state), "Rain", "/test");
        let reply_html = reply_form("test", 42, "csrf", &board, Some(&state), "Rain");
        for html in [&thread_html, &reply_html] {
            assert!(
                html.contains(r#"name="anonymous" value="1" checked"#),
                "the choice made with a rejected submission must come back with it"
            );
            assert!(
                html.contains("se&#231;ilen isim") || html.contains("seçilen isim"),
                "the chosen name must come back with the rejected submission"
            );
        }
        Ok(())
    }

    #[test]
    fn captcha_row_uses_server_side_image_challenge() {
        let html = new_thread_form(
            "test",
            "csrf",
            &crate::models::Board {
                allow_captcha: true,
                ..uploads_disabled_board()
            },
            None,
            "Rain",
            "/test",
        );

        assert!(html.contains("name=\"captcha_id\""));
        assert!(html.contains("name=\"captcha_answer\""));
        assert!(html.contains("/captcha/"));
        assert!(html.contains("?captcha_refresh="));
        assert!(html.contains("yeni doğrulama"));
        assert!(!html.contains("pow_nonce"));
    }

    #[test]
    fn captcha_refresh_query_precedes_reply_form_fragment() {
        let html = render_captcha_row("test", "-reply", "/test/thread/7#post-form-wrap");

        assert!(html.contains("/test/thread/7?captcha_refresh="));
        assert!(html.contains("#post-form-wrap\">yeni doğrulama</a>"));
    }
}
