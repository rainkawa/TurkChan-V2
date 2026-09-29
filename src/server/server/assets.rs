//! Embedded static-asset handlers.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
};

/// Embedded public stylesheet.
static STYLE_CSS: &str = include_str!("../../../static/style.css");
/// Embedded social design layer.
///
/// A second stylesheet rather than a rewrite: the board's own sheet still owns
/// the themes, the thread markup, and the administration panels, and this one
/// is loaded after it to give the reading surfaces the shape a phone needs.
/// It has to be served from its own route — a stylesheet nobody routes is a
/// stylesheet nobody ever sees, which is the difference between a design and
/// a file.
static SOCIAL_CSS: &str = include_str!("../../../static/social.css");
/// Embedded public JavaScript bundle.
static MAIN_JS: &str = include_str!("../../../static/main.js");
/// Embedded registration-wizard JavaScript enhancement.
static AUTH_JS: &str = include_str!("../../../static/auth.js");
/// Embedded administrator stylesheet.
static ADMIN_CSS: &str = include_str!("../../../static/admin.css");
/// Embedded administrator JavaScript bundle.
static ADMIN_JS: &str = include_str!("../../../static/admin.js");
/// Embedded pre-render theme initializer.
static THEME_INIT_JS: &str = include_str!("../../../static/theme-init.js");

/// Return whether a request carries the current asset-version query.
fn valid_version_query(req: &axum::extract::Request) -> bool {
    req.uri().query().is_some_and(|query| {
        query.split('&').any(|part| {
            part.strip_prefix("v=")
                .is_some_and(crate::templates::static_asset_version_matches)
        })
    })
}

/// Build a cache-aware embedded static-asset response.
fn static_asset_response(
    req: &axum::extract::Request,
    body: &'static str,
    content_type: &'static str,
) -> impl IntoResponse + use<> {
    let cache_control = if valid_version_query(req) {
        crate::cache::CACHE_CONTROL_IMMUTABLE_MEDIA
    } else {
        crate::cache::CACHE_CONTROL_STATIC_SHORT
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(cache_control),
            ),
        ],
        body,
    )
}

/// Serve the public stylesheet.
pub(super) async fn serve_css(req: axum::extract::Request) -> impl IntoResponse {
    static_asset_response(&req, STYLE_CSS, "text/css; charset=utf-8")
}

/// Serve the public JavaScript bundle.
pub(super) async fn serve_main_js(req: axum::extract::Request) -> impl IntoResponse {
    static_asset_response(&req, MAIN_JS, "application/javascript; charset=utf-8")
}

/// Serve the social design layer.
pub(super) async fn serve_social_css(req: axum::extract::Request) -> impl IntoResponse {
    static_asset_response(&req, SOCIAL_CSS, "text/css; charset=utf-8")
}

/// Serve the registration-wizard JavaScript enhancement.
pub(super) async fn serve_auth_js(req: axum::extract::Request) -> impl IntoResponse {
    static_asset_response(&req, AUTH_JS, "application/javascript; charset=utf-8")
}

/// Serve the administrator stylesheet.
pub(super) async fn serve_admin_css(req: axum::extract::Request) -> impl IntoResponse {
    static_asset_response(&req, ADMIN_CSS, "text/css; charset=utf-8")
}

/// Serve the administrator JavaScript bundle.
pub(super) async fn serve_admin_js(req: axum::extract::Request) -> impl IntoResponse {
    static_asset_response(&req, ADMIN_JS, "application/javascript; charset=utf-8")
}

/// Serve the pre-render theme initializer.
pub(super) async fn serve_theme_init_js(req: axum::extract::Request) -> impl IntoResponse {
    static_asset_response(&req, THEME_INIT_JS, "application/javascript; charset=utf-8")
}

#[cfg(test)]
/// Embedded asset contract tests.
mod tests {
    use super::{MAIN_JS, SOCIAL_CSS, STYLE_CSS};

    #[test]
    /// The social layer carries the shell the reading surfaces are built from.
    ///
    /// Every selector here was in a file the layout linked but nothing served,
    /// so the whole design was absent while every test still passed. The layer
    /// is now routed, and this pins the pieces that make it a phone rather
    /// than a wide board with a strip under it.
    fn social_layer_carries_the_shell_the_layout_links() {
        for expected in [
            ".tabbar {\n",
            "grid-template-columns: repeat(5, 1fr);",
            "position: fixed;",
            "env(safe-area-inset-bottom, 0px)",
            ".post-card {\n",
            ".profile-cover {",
            ".profile-metrics {",
            "grid-template-columns: repeat(3, 1fr);",
            "@media (max-width: 400px)",
            "@media (prefers-reduced-motion: reduce)",
        ] {
            assert!(
                SOCIAL_CSS.contains(expected),
                "the social layer should contain {expected:?}"
            );
        }
    }

    #[test]
    /// Keeps the mobile preferences sheet within the viewport.
    fn stylesheet_uses_mobile_sheet_for_user_preferences_panel() {
        for expected in [
            ".user-preferences-form {\n",
            "max-height: calc(100vh - 24px);",
            "overflow-y: auto;",
            ".user-preferences-panel[open]::before",
            "body.user-preferences-mobile-open {\n    overflow: hidden;",
            "background: rgba(0,0,0,0.42);",
            ".user-preferences-mobile-close {\n  display: none;",
            "visibility: hidden;",
            ".user-preferences-panel[open] .user-preferences-form {\n    position: fixed;"
            ,"bottom: 0;",
            "inset-block-end: 0;",
            "margin: 0 auto;",
            "transform: translate3d(0, 0, 0);",
            "max-width: 30rem;",
            "max-height: min(68svh, calc(100svh - max(20px, env(safe-area-inset-top))));",
            "overflow-x: hidden;",
            "border-radius: 18px 18px 0 0;",
            "position: sticky;",
            ".user-preferences-form > label {\n    min-height: 46px;",
            ".user-preferences-form input[type=\"checkbox\"],\n  .user-preferences-form input[type=\"radio\"] {\n    min-width: 24px;",
        ] {
            assert!(
                STYLE_CSS.contains(expected),
                "public stylesheet should contain {expected:?}"
            );
        }
        assert!(
            !STYLE_CSS.contains(".user-preferences-form button[type=\"submit\"]"),
            "preferences styling should not depend on a submit button"
        );
    }

    #[test]
    /// Persists public preferences progressively in the browser.
    fn main_js_progressively_persists_user_preference_changes() {
        for expected in [
            "function initUserPreferencesForms()",
            "function mirrorUserPreferencesToCookies(form)",
            "setPublicPreferenceCookie('rustchan_theme', theme.value);",
            "setPublicPreferenceCookie('rustchan_preferred_view', boardView.value);",
            "x-rustchan-background",
            "keepalive: true",
            "new URLSearchParams(new FormData(form))",
            "setPreferenceStatus('Saving…', 'saving');",
            "setPreferenceStatus('Saved.', 'saved');",
            "control.name === 'theme'",
            "control.name === 'hide_nsfw_boards'",
            "data-hide-nsfw-boards",
            "var mobileClose = panel.querySelector('.user-preferences-mobile-close');",
            "function syncUserPreferencesBackgroundScrollLock()",
            "document.body.style.position = 'fixed';",
            "window.scrollTo(0, scrollY);",
            "panel.open = false;",
        ] {
            assert!(
                MAIN_JS.contains(expected),
                "public JavaScript should contain {expected:?}"
            );
        }
        assert!(
            !MAIN_JS.contains("var firstControl = panel.querySelector('select, input, button');"),
            "opening preferences should not force focus onto the first control"
        );
        assert!(
            !MAIN_JS.contains(
                "form.addEventListener('submit', function (event) {\n        event.preventDefault();\n        mirrorUserPreferencesToCookies(form);"
            ),
            "preferences should persist on change without a redundant submit flow"
        );
    }

    #[test]
    /// Keeps mobile dialogs and quote popups within the viewport.
    fn stylesheet_keeps_mobile_dialogs_and_popups_inside_viewport() {
        for expected in [
            "@media (max-width: 700px) {\n  .quotelink-popup {",
            "max-width: calc(100vw - 16px);",
            "max-height: min(70vh, 26rem);",
            ".edit-modal,\n  .compress-modal {",
            "align-items: flex-start;",
            "padding: max(12px, env(safe-area-inset-top)) 12px max(12px, env(safe-area-inset-bottom));"
            ,".edit-modal-box,\n  .compress-modal-box {",
            "max-height: calc(100svh - 24px - env(safe-area-inset-top) - env(safe-area-inset-bottom));"
            ,".edit-modal-box .post-form td:last-child {",
            ".edit-modal-box .edit-btn[data-action=\"close-edit-modal\"]",
        ] {
            assert!(
                STYLE_CSS.contains(expected),
                "public stylesheet should contain {expected:?}"
            );
        }
    }

    #[test]
    /// Positions mobile menus against the visual viewport.
    fn main_js_positions_mobile_menus_and_popups_against_visual_viewport() {
        for expected in [
            "function getThreadMenuBounds(gutter)",
            "window.visualViewport && window.visualViewport.height",
            "function clampPopupToViewport(anchor, popup)",
            "visualViewport.offsetLeft",
            "visualViewport.offsetTop",
            "var minTop = viewportTop + gutter;",
            "var maxTop = viewportTop + Math.max(gutter, vh - ph - gutter);",
            "var position = clampPopupToViewport(anchor, popup);",
            "window.visualViewport.addEventListener('resize', repositionOpenThreadMenus);",
            "window.visualViewport.addEventListener('scroll', repositionOpenThreadMenus);",
        ] {
            assert!(
                MAIN_JS.contains(expected),
                "public JavaScript should contain {expected:?}"
            );
        }
    }
}
