//! Registry of themes bundled with `RustChan`.
//!
//! TurkChan ships a single built-in design. The palette itself lives in
//! `static/style.css`, which answers the light and dark halves of the same
//! design through a `data-color-mode` attribute; this module only registers the
//! slug the rest of the application resolves against. Administrators can still
//! add themes of their own, which are stored beside it.

use crate::models::Theme;

/// Metadata for a theme shipped with `RustChan`.
#[derive(Debug)]
pub struct BuiltinTheme {
    /// Stable identifier used in configuration and URLs.
    pub slug: &'static str,
    /// Human-readable theme name.
    pub display_name: &'static str,
    /// Short description shown in theme selectors.
    pub description: &'static str,
    /// Representative CSS color for theme previews.
    pub swatch_hex: &'static str,
    /// Display order relative to other built-in themes.
    pub sort_order: i64,
}

/// Theme used when no configured default can be resolved.
pub const HARD_DEFAULT_THEME: &str = "aurora";

/// The built-in design.
pub const BUILTIN_THEMES: &[BuiltinTheme] = &[BuiltinTheme {
    slug: HARD_DEFAULT_THEME,
    display_name: "Aurora",
    description: "Modern violet dark palette with a light mode, readable at any size.",
    swatch_hex: "#8b5cf6",
    sort_order: 10,
}];

#[must_use]
/// Find a built-in theme by slug, ignoring ASCII case and surrounding space.
pub fn builtin_theme(slug: &str) -> Option<&'static BuiltinTheme> {
    BUILTIN_THEMES
        .iter()
        .find(|theme| theme.slug.eq_ignore_ascii_case(slug.trim()))
}

#[must_use]
/// Return the stable slugs of all built-in themes in display order.
pub fn builtin_theme_slugs() -> Vec<&'static str> {
    BUILTIN_THEMES.iter().map(|theme| theme.slug).collect()
}

#[must_use]
/// Build database-compatible theme rows with configured enablement state.
pub fn builtin_theme_rows(enabled_slugs: &[String]) -> Vec<Theme> {
    BUILTIN_THEMES
        .iter()
        .map(|theme| Theme {
            slug: theme.slug.to_owned(),
            display_name: theme.display_name.to_owned(),
            description: theme.description.to_owned(),
            swatch_hex: theme.swatch_hex.to_owned(),
            enabled: enabled_slugs
                .iter()
                .any(|slug| slug.eq_ignore_ascii_case(theme.slug)),
            sort_order: theme.sort_order,
            is_builtin: true,
            custom_css: String::new(),
        })
        .collect()
}

#[must_use]
/// Return whether a slug names a theme this build no longer ships.
///
/// A database keeps the rows it was seeded with. When a built-in design is
/// retired the row stays behind, and because the theme resolver matches on the
/// row rather than on the registry, a visitor whose cookie still named the old
/// design would be served a `data-theme` no stylesheet answers to. This is what
/// the seeding step uses to recognise those rows.
pub fn is_retired_builtin_slug(slug: &str) -> bool {
    const RETIRED: &[&str] = &[
        "aero",
        "blue-sky",
        "chanclassic",
        "deep-orbit",
        "dorfic",
        "fluorogrid",
        "forest",
        "neoncubicle",
        "terminal",
    ];
    builtin_theme(slug).is_none() && RETIRED.iter().any(|name| name.eq_ignore_ascii_case(slug))
}
