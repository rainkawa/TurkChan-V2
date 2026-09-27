//! Board-directory and board-creation sections of the admin panel.

use super::{escape_html, render_board_settings_card, AdminPanelViewModel};

/// Renders the complete boards tab of the admin panel.
pub(super) fn render(view: &AdminPanelViewModel<'_>) -> String {
    let boards_open_attr = if view.open_section == Some("boards")
        || view
            .open_section
            .is_some_and(|section| section.starts_with("board-"))
    {
        " open"
    } else {
        ""
    };
    let mut board_cards = String::new();
    for (index, board) in view.boards.iter().enumerate() {
        let board_assets = view
            .appearance
            .board_banners
            .iter()
            .filter(|asset| {
                asset.scope == crate::models::BannerScope::Board && asset.board_id == Some(board.id)
            })
            .cloned()
            .collect::<Vec<_>>();
        board_cards.push_str(&render_board_settings_card(
            board,
            index,
            view.boards,
            view.csrf_token,
            view.appearance.themes,
            &board_assets,
            view.open_section,
        ));
    }

    render_admin_boards_section(view.csrf_token, &board_cards, boards_open_attr)
}

/// Renders the board directory and quick-create form.
fn render_admin_boards_section(
    csrf_token: &str,
    board_cards: &str,
    boards_open_attr: &str,
) -> String {
    format!(
        r#"<div class="admin-panel-boards" id="boards">
<section class="admin-section admin-section-collapsible">
<details class="admin-dropdown" data-admin-dropdown-key="boards"{boards_open_attr}>
<summary><span>// boardlar</span></summary>
<div class="admin-dropdown-content">
<div class="admin-subsection">
  <div class="admin-card-header">
    <h3>// board dizini</h3>
  <p>Bir board’u açıp ayarlarını düzenle.</p>
  </div>
  <p class="admin-order-note">Board sırası ana sayfa, üst çubuk ve bu panel arasında ortaktır. SFW ve NSFW boardlar kendi sıralamalarını korur.</p>
  <div class="admin-board-cards">{board_cards}</div>
</div>
<div class="admin-subsection">
  <div class="admin-card-header">
    <h3>// board oluştur</h3>
    <p>Kısa ad ve etiketle başla, kalanını yukarıdaki board kartından düzenle.</p>
  </div>
  <form method="POST" action="/admin/board/create" class="admin-board-create-form admin-quick-form">
  <input type="hidden" name="_csrf" value="{csrf}">
  <label class="admin-quick-field">Kısa ad
    <input type="text" name="short_name" maxlength="8" required placeholder="tech">
  </label>
  <label class="admin-quick-field">Görünen ad
    <input type="text" name="name" maxlength="64" required placeholder="Teknoloji">
  </label>
  <label class="admin-quick-field">Açıklama
    <input type="text" name="description" maxlength="256" placeholder="Programlama, donanım ve internet kültürü">
  </label>
  <label class="admin-inline-checkbox admin-quick-checkbox"><input type="checkbox" name="nsfw" value="1"> NSFW board</label>
  <label class="admin-inline-checkbox admin-quick-checkbox"><input type="checkbox" name="allow_audio" value="1"> Ses yüklemelerini etkinleştir</label>
  <button type="submit">oluştur</button>
  </form>
</div>
</div>
</details>
</section>
</div>"#,
        board_cards = board_cards,
        csrf = escape_html(csrf_token),
        boards_open_attr = boards_open_attr,
    )
}
