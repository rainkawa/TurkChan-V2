//! Account roles, the permissions behind them, and the badge an account shows.
//!
//! Three separate things are answered here, and keeping them apart is what
//! makes the model granular rather than a single ladder:
//!
//!   * The **staff role** is stored on the account row. Only an operator
//!     changes it, and it is the only thing that decides who may reach the
//!     administration panel.
//!   * The **trust tier** is derived from the account's karma. It moves on its
//!     own as votes come in, and no one assigns it.
//!   * The **status** sits over both. A banned or suspended account is shown
//!     as such whatever its role or karma say, because that is the state a
//!     visitor needs to see first.
//!
//! Permissions are a separate enum from the role, so a role is a named bundle
//! of permissions and a check reads as "may this role delete any post" rather
//! than "is this role at least moderator". Adding a permission does not require
//! inventing a new role, and a handler names exactly the one it needs.

use serde::{Deserialize, Serialize};

/// Karma at which an account becomes an Angel.
pub const ANGEL_KARMA: i64 = 101;
/// Karma at which an account becomes a Legend.
pub const LEGEND_KARMA: i64 = 201;
/// Karma at which an account becomes a God.
pub const GOD_KARMA: i64 = 451;
/// Longest suspension an operator may set, in seconds (30 days).
///
/// A suspension is a temporary measure; anything longer is a ban, which is a
/// separate action with its own record.
pub const MAX_SUSPEND_SECS: i64 = 30 * 24 * 60 * 60;

/// One thing an account role may be allowed to do.
///
/// A handler asks for the single permission it is about to use, so the
/// authorization for a route is visible at the point the action happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Open a thread or write a post.
    Post,
    /// Attach an upload to a post.
    UploadMedia,
    /// Open the administration panel.
    AccessAdminPanel,
    /// Delete a post written by anyone.
    DeleteAnyPost,
    /// Lock, pin, or delete a thread.
    ModerateThreads,
    /// Resolve a report or answer an appeal.
    ResolveReports,
    /// Change another account's display name or username.
    RenameAccount,
    /// Set a new password for another account.
    ResetAccountPassword,
    /// Suspend another account for a while.
    SuspendAccount,
    /// Ban or unban an account.
    BanAccount,
    /// Change the staff role of an account.
    AssignRoles,
    /// Create, edit, reorder, or delete a board.
    ManageBoards,
    /// Change site-wide settings, themes, or filters.
    ManageSiteSettings,
    /// Create, download, or delete a backup.
    ManageBackups,
    /// Restore a backup over the live database.
    RestoreDatabase,
}

/// The stored staff role of an account.
///
/// Members of the public carry [`UserRole::User`]; the other three are granted
/// from the administration panel and are what a permission check reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    /// An ordinary member.
    #[default]
    User,
    /// Tends the board: deletes posts, resolves reports, suspends accounts.
    Moderator,
    /// Runs the site: the moderator's tools plus roles, passwords, bans, boards.
    Admin,
    /// The site owner: every permission, including handing out ownership.
    Owner,
}

impl UserRole {
    /// Every role, in ascending order of authority.
    pub const ALL: [Self; 4] = [Self::User, Self::Moderator, Self::Admin, Self::Owner];

    /// The stored name of the role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Moderator => "moderator",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    /// The name shown next to an account.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::User => "Kullanıcı",
            Self::Moderator => "Moderatör",
            Self::Admin => "Admin",
            Self::Owner => "Owner",
        }
    }

    /// Read a role from its stored name, falling back to `User`.
    ///
    /// An unreadable name is never trusted: a row that somehow holds a role
    /// this build does not know is treated as an ordinary member rather than
    /// as the highest role that might have been meant.
    #[must_use]
    pub fn from_stored(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "moderator" => Self::Moderator,
            "admin" => Self::Admin,
            "owner" => Self::Owner,
            _ => Self::User,
        }
    }

    /// Whether this role carries `permission`.
    ///
    /// [`UserRole::Owner`] carries everything, including permissions added
    /// after this release, so ownership never has to be revisited when the
    /// permission list grows.
    #[must_use]
    pub fn has(self, permission: Permission) -> bool {
        match self {
            Self::Owner => true,
            Self::Admin => matches!(
                permission,
                Permission::Post
                    | Permission::UploadMedia
                    | Permission::AccessAdminPanel
                    | Permission::DeleteAnyPost
                    | Permission::ModerateThreads
                    | Permission::ResolveReports
                    | Permission::RenameAccount
                    | Permission::ResetAccountPassword
                    | Permission::SuspendAccount
                    | Permission::BanAccount
                    | Permission::AssignRoles
                    | Permission::ManageBoards
                    | Permission::ManageSiteSettings
            ),
            Self::Moderator => matches!(
                permission,
                Permission::Post
                    | Permission::UploadMedia
                    | Permission::AccessAdminPanel
                    | Permission::DeleteAnyPost
                    | Permission::ModerateThreads
                    | Permission::ResolveReports
                    | Permission::RenameAccount
                    | Permission::SuspendAccount
            ),
            Self::User => matches!(permission, Permission::Post | Permission::UploadMedia),
        }
    }

    /// Whether this role may open the administration panel.
    #[must_use]
    pub const fn reaches_admin_panel(self) -> bool {
        matches!(self, Self::Moderator | Self::Admin | Self::Owner)
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The karma tier an account has earned on its own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Zero to fifty karma.
    #[default]
    User,
    /// Fifty-one to a hundred karma.
    Verified,
    /// A hundred and one to two hundred karma.
    Angel,
    /// Two hundred and one to four hundred and fifty karma.
    Legend,
    /// More than four hundred and fifty karma.
    God,
}

impl TrustTier {
    /// The tier a karma score earns.
    #[must_use]
    pub const fn for_karma(karma: i64) -> Self {
        if karma >= GOD_KARMA {
            Self::God
        } else if karma >= LEGEND_KARMA {
            Self::Legend
        } else if karma >= ANGEL_KARMA {
            Self::Angel
        } else if karma >= 51 {
            Self::Verified
        } else {
            Self::User
        }
    }

    /// The name shown on the badge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Verified => "Verified User",
            Self::Angel => "Angel",
            Self::Legend => "Legend",
            Self::God => "God",
        }
    }

    /// The karma at which this tier begins.
    #[must_use]
    pub const fn minimum_karma(self) -> i64 {
        match self {
            Self::User => 0,
            Self::Verified => 51,
            Self::Angel => ANGEL_KARMA,
            Self::Legend => LEGEND_KARMA,
            Self::God => GOD_KARMA,
        }
    }
}

/// The moderation state an account is in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// May sign in and act.
    #[default]
    Active,
    /// May sign in, but may not post, until the suspension expires.
    Suspended,
    /// May not sign in at all.
    Banned,
}

impl AccountStatus {
    /// Read a status from its stored name, falling back to `Active`.
    ///
    /// An unreadable name is treated as `Active` so a damaged row cannot lock
    /// every account out of the site.
    #[must_use]
    pub fn from_stored(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "banned" => Self::Banned,
            "suspended" => Self::Suspended,
            _ => Self::Active,
        }
    }

    /// The stored name of the status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Banned => "banned",
        }
    }

    /// The status an account is in right now.
    ///
    /// A suspension is stored with the second it ends, so it lifts on its own
    /// and nobody has to remember to clear it.
    #[must_use]
    pub const fn effective(self, suspended_until: Option<i64>, now: i64) -> Self {
        if matches!(self, Self::Banned) {
            return Self::Banned;
        }
        match suspended_until {
            Some(until) if until > now => Self::Suspended,
            _ => Self::Active,
        }
    }

    /// Whether an account in this state may sign in.
    #[must_use]
    pub const fn may_sign_in(self) -> bool {
        !matches!(self, Self::Banned)
    }

    /// Whether an account in this state may post.
    #[must_use]
    pub const fn may_post(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// The single badge an account shows next to its name.
///
/// The badge is resolved once, in priority order, so a page never has to
/// decide for itself which of the three things wins: a suspended owner reads
/// as suspended, because that is the state a visitor has to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleBadge {
    /// Banned.
    Banned,
    /// Suspended until a given time.
    Suspended,
    /// The site owner.
    Owner,
    /// An administrator.
    Admin,
    /// A moderator.
    Moderator,
    /// Four hundred and fifty-one karma or more.
    God,
    /// Two hundred and one to four hundred and fifty karma.
    Legend,
    /// A hundred and one to two hundred karma.
    Angel,
    /// Fifty-one to a hundred karma.
    Verified,
    /// Zero to fifty karma.
    User,
}

impl RoleBadge {
    /// Resolve the badge shown for an account.
    #[must_use]
    pub const fn resolve(role: UserRole, status: AccountStatus, karma: i64) -> Self {
        match status {
            AccountStatus::Banned => Self::Banned,
            AccountStatus::Suspended => Self::Suspended,
            AccountStatus::Active => match role {
                UserRole::Owner => Self::Owner,
                UserRole::Admin => Self::Admin,
                UserRole::Moderator => Self::Moderator,
                UserRole::User => Self::tier_for_karma(karma),
            },
        }
    }

    /// The karma tier as a badge, without the moderation states.
    const fn tier_for_karma(karma: i64) -> Self {
        match TrustTier::for_karma(karma) {
            TrustTier::God => Self::God,
            TrustTier::Legend => Self::Legend,
            TrustTier::Angel => Self::Angel,
            TrustTier::Verified => Self::Verified,
            TrustTier::User => Self::User,
        }
    }

    /// The name shown on the badge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Banned => "Banned",
            Self::Suspended => "Suspended",
            Self::Owner => "Owner",
            Self::Admin => "Admin",
            Self::Moderator => "Moderator",
            Self::God => "God",
            Self::Legend => "Legend",
            Self::Angel => "Angel",
            Self::Verified => "Verified User",
            Self::User => "User",
        }
    }

    /// The colour the badge is drawn in.
    #[must_use]
    pub const fn color(self) -> &'static str {
        match self {
            Self::Banned => "#14161a",
            Self::Suspended => "#8b8f96",
            Self::Owner => "#d92b2b",
            Self::Admin => "#7b1e3a",
            Self::Moderator => "#2e9e5b",
            Self::God => "#8b5cd6",
            Self::Legend => "#3d8bd4",
            Self::Angel => "#e0a92e",
            Self::Verified => "#efe3c2",
            Self::User => "#f2f5f7",
        }
    }

    /// Whether a badge colour is dark, so its label is drawn light on top.
    #[must_use]
    pub const fn is_dark(self) -> bool {
        !matches!(self, Self::Verified | Self::User)
    }
}

#[cfg(test)]
/// The tier boundaries and the permission bundles are the whole point of the
/// module, so they are pinned rather than left to be re-derived.
mod tests {
    use super::{
        AccountStatus, Permission, RoleBadge, TrustTier, UserRole, ANGEL_KARMA, GOD_KARMA,
        LEGEND_KARMA, MAX_SUSPEND_SECS,
    };

    #[test]
    /// Karma decides the tier, and each boundary belongs to the tier above it.
    fn karma_boundaries_pick_the_documented_tier() {
        assert_eq!(TrustTier::for_karma(0), TrustTier::User);
        assert_eq!(TrustTier::for_karma(50), TrustTier::User);
        assert_eq!(TrustTier::for_karma(51), TrustTier::Verified);
        assert_eq!(TrustTier::for_karma(100), TrustTier::Verified);
        assert_eq!(TrustTier::for_karma(ANGEL_KARMA), TrustTier::Angel);
        assert_eq!(TrustTier::for_karma(200), TrustTier::Angel);
        assert_eq!(TrustTier::for_karma(LEGEND_KARMA), TrustTier::Legend);
        assert_eq!(TrustTier::for_karma(450), TrustTier::Legend);
        assert_eq!(TrustTier::for_karma(GOD_KARMA), TrustTier::God);
        assert_eq!(TrustTier::for_karma(100_000), TrustTier::God);
        // A negative score from downvotes is still just an ordinary account.
        assert_eq!(TrustTier::for_karma(-40), TrustTier::User);
    }

    #[test]
    /// Each role carries exactly the permissions it is documented to carry, so
    /// granting a role cannot quietly widen something else.
    fn roles_carry_their_documented_permissions() {
        assert!(UserRole::User.has(Permission::Post));
        assert!(!UserRole::User.has(Permission::AccessAdminPanel));
        assert!(!UserRole::User.has(Permission::DeleteAnyPost));

        assert!(UserRole::Moderator.has(Permission::AccessAdminPanel));
        assert!(UserRole::Moderator.has(Permission::DeleteAnyPost));
        assert!(UserRole::Moderator.has(Permission::SuspendAccount));
        assert!(!UserRole::Moderator.has(Permission::ResetAccountPassword));
        assert!(!UserRole::Moderator.has(Permission::BanAccount));
        assert!(!UserRole::Moderator.has(Permission::AssignRoles));

        assert!(UserRole::Admin.has(Permission::BanAccount));
        assert!(UserRole::Admin.has(Permission::AssignRoles));
        assert!(UserRole::Admin.has(Permission::ManageBoards));
        assert!(!UserRole::Admin.has(Permission::RestoreDatabase));

        assert!(
            UserRole::Owner.has(Permission::RestoreDatabase),
            "the owner keeps every permission, including ones added later"
        );
    }

    #[test]
    /// Only the three staff roles reach the administration panel.
    fn only_staff_roles_reach_the_admin_panel() {
        assert!(!UserRole::User.reaches_admin_panel());
        assert!(UserRole::Moderator.reaches_admin_panel());
        assert!(UserRole::Admin.reaches_admin_panel());
        assert!(UserRole::Owner.reaches_admin_panel());
    }

    #[test]
    /// An unknown stored name is the least authority, not the greatest, so a
    /// damaged row cannot promote itself.
    fn an_unreadable_stored_role_is_an_ordinary_account() {
        assert_eq!(UserRole::from_stored("owner"), UserRole::Owner);
        assert_eq!(UserRole::from_stored("  ADMIN "), UserRole::Admin);
        assert_eq!(UserRole::from_stored("moderator"), UserRole::Moderator);
        assert_eq!(UserRole::from_stored("superuser"), UserRole::User);
        assert_eq!(UserRole::from_stored(""), UserRole::User);
        assert_eq!(UserRole::from_stored("'; DROP TABLE users; --"), UserRole::User);
    }

    #[test]
    /// An unreadable stored status leaves the account usable, because a status
    /// row that cannot be read must not lock every account out of the site.
    fn an_unreadable_stored_status_is_active() {
        assert_eq!(AccountStatus::from_stored("banned"), AccountStatus::Banned);
        assert_eq!(AccountStatus::from_stored("SUSPENDED"), AccountStatus::Suspended);
        assert_eq!(AccountStatus::from_stored("nonsense"), AccountStatus::Active);
    }

    #[test]
    /// A suspension lifts by itself when its moment passes, and a ban does not
    /// lift at any moment.
    fn a_suspension_expires_on_its_own() {
        let now = 1_000;
        assert_eq!(
            AccountStatus::Suspended.effective(Some(now + 60), now),
            AccountStatus::Suspended
        );
        assert_eq!(
            AccountStatus::Suspended.effective(Some(now), now),
            AccountStatus::Active,
            "a suspension whose moment has passed is over"
        );
        assert_eq!(
            AccountStatus::Suspended.effective(None, now),
            AccountStatus::Active
        );
        assert_eq!(
            AccountStatus::Banned.effective(None, now),
            AccountStatus::Banned,
            "a ban is not a suspension and never expires on a timer"
        );
    }

    #[test]
    /// The badge is one thing resolved in priority order, so a page never has
    /// to choose between a role and a state.
    fn the_badge_prefers_state_over_role_over_karma() {
        assert_eq!(
            RoleBadge::resolve(UserRole::Owner, AccountStatus::Banned, 0),
            RoleBadge::Banned,
            "a banned owner is shown as banned, not as the owner"
        );
        assert_eq!(
            RoleBadge::resolve(UserRole::Admin, AccountStatus::Suspended, 0),
            RoleBadge::Suspended
        );
        assert_eq!(RoleBadge::resolve(UserRole::Owner, AccountStatus::Active, 0), RoleBadge::Owner);
        assert_eq!(RoleBadge::resolve(UserRole::Moderator, AccountStatus::Active, 0), RoleBadge::Moderator);
        assert_eq!(
            RoleBadge::resolve(UserRole::User, AccountStatus::Active, 0),
            RoleBadge::User
        );
        assert_eq!(
            RoleBadge::resolve(UserRole::User, AccountStatus::Active, 500),
            RoleBadge::God,
            "a member's badge is the karma tier they have earned"
        );
    }

    #[test]
    /// Every badge carries a label and a colour, and the two readable-against
    /// the dark background badges are marked as light.
    fn every_badge_is_labelled_and_coloured() {
        use RoleBadge::{
            Admin, Angel, Banned, God, Legend, Moderator, Owner, Suspended, User, Verified,
        };
        for badge in [
            Banned, Suspended, Owner, Admin, Moderator, God, Legend, Angel, Verified, User,
        ] {
            assert!(!badge.label().is_empty(), "{badge:?} needs a label");
            assert!(
                badge.color().starts_with('#') && badge.color().len() == 7,
                "{badge:?} needs a colour, got {}",
                badge.color()
            );
        }
        assert!(!Verified.is_dark() && !User.is_dark());
        assert!(Banned.is_dark() && God.is_dark());
    }

    #[test]
    /// A suspension is bounded, so the form cannot be used to write a ban that
    /// is not recorded as one.
    fn a_suspension_is_bounded_by_the_ban_threshold() {
        assert!(MAX_SUSPEND_SECS <= 31 * 24 * 60 * 60);
        assert_eq!(MAX_SUSPEND_SECS, 30 * 24 * 60 * 60);
    }
}
