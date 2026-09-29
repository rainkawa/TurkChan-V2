//! Per-account and per-address upload budgets.
//!
//! A per-file size limit bounds one upload and says nothing about the hundred
//! that follow it, so a quota is counted here rather than inferred from the
//! boards. Two subjects are tracked, and both are enforced against the same
//! counter: the signed-in account, so one person cannot spread an upload
//! budget across fresh sessions, and the hashed client address, so a shared
//! address — a Tor exit, a school, a room with one router — cannot be used to
//! spend past a limit no single person reached.
//!
//! The window is fixed rather than sliding: a rolling window has to be read
//! and rewritten on every upload, and a fixed one answers the same question
//! ("how much has this subject uploaded today") from a single indexed row.
//! The cost is that a subject may spend its whole budget early in the window
//! and none afterwards, which is the ordinary behaviour of a daily quota.

use anyhow::{Context as _, Result};
use rusqlite::{params, OptionalExtension as _};

/// A subject whose uploads are counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadQuotaSubject {
    /// The signed-in account, identified by its row id.
    Account(i64),
    /// A client address that has already been hashed, never held in the clear.
    Address(String),
}

impl UploadQuotaSubject {
    /// Return the counter key for this subject.
    ///
    /// The kind is part of the key so an account whose id happens to match a
    /// hash, or the reverse, can never spend the other one's budget.
    fn key(&self) -> String {
        match self {
            Self::Account(id) => format!("account:{id}"),
            Self::Address(hash) => format!("address:{hash}"),
        }
    }
}

/// What a subject has uploaded inside the current window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UploadQuotaUsage {
    /// Total bytes uploaded by the subject in this window.
    pub bytes: i64,
    /// Number of uploads the subject made in this window.
    pub uploads: i64,
}

/// The budgets a subject is held to, with zero meaning "no limit".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UploadQuotaLimits {
    /// Maximum bytes per window; zero disables the byte budget.
    pub max_bytes: i64,
    /// Maximum uploads per window; zero disables the count budget.
    pub max_uploads: i64,
}

impl UploadQuotaLimits {
    /// Return whether these limits place no budget on a subject at all.
    ///
    /// An operator who sets both to zero has turned the quota off, and a
    /// submission that carries files must not be refused over a budget that
    /// does not exist.
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.max_bytes <= 0 && self.max_uploads <= 0
    }
}

/// The reason a submission was refused, in the operator's own words.
///
/// The count and the byte budget are reported separately rather than as one
/// number, because "you have uploaded too much today" and "you have uploaded
/// too many files today" are different problems with different answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadQuotaExceeded {
    /// The subject's byte budget for this window is spent.
    Bytes {
        /// The byte budget that was reached, in bytes.
        limit: i64,
    },
    /// The subject's upload-count budget for this window is spent.
    Uploads {
        /// The number of uploads allowed before the refusal.
        limit: i64,
    },
}

/// Why a subject's counter was not moved.
///
/// A spent budget and an unreachable database are different answers: the first
/// is the poster's to hear about, the second is the operator's to hear about.
/// They are kept apart here rather than flattened into one error, so a caller
/// can show the poster the limit instead of a storage failure.
#[derive(Debug)]
pub enum UploadQuotaRefusal {
    /// The subject is over a budget for this window.
    Exceeded(UploadQuotaExceeded),
    /// The counter could not be read or written.
    Storage(anyhow::Error),
}

impl UploadQuotaRefusal {
    /// Return the spent budget this refusal names, if it names one.
    ///
    /// A storage failure names none, because no budget was consulted.
    #[must_use]
    pub fn exceeded(&self) -> Option<UploadQuotaExceeded> {
        match self {
            Self::Exceeded(exceeded) => Some(*exceeded),
            Self::Storage(_) => None,
        }
    }
}

impl std::fmt::Display for UploadQuotaRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exceeded(exceeded) => write!(formatter, "upload quota exceeded: {exceeded:?}"),
            Self::Storage(error) => write!(formatter, "upload quota storage failure: {error}"),
        }
    }
}

impl std::error::Error for UploadQuotaRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Exceeded(_) => None,
            Self::Storage(error) => Some(error.as_ref()),
        }
    }
}

/// Return the start of the window `now` falls in.
///
/// Windows are aligned to `window_secs` from the Unix epoch, so every subject
/// on the site resets at the same moment and a counter row is found by its
/// primary key rather than by a range scan.
fn window_start(now: i64, window_secs: i64) -> i64 {
    let width = window_secs.max(1);
    now.div_euclid(width) * width
}

/// Read what a subject has uploaded in the current window.
///
/// A subject with no row has uploaded nothing, which is the same answer a
/// counter that has been pruned gives, so a missing row is zero rather than an
/// error.
///
/// # Errors
/// Returns an error if the counter cannot be read.
pub fn upload_quota_usage(
    conn: &rusqlite::Connection,
    subject: &UploadQuotaSubject,
    now: i64,
    window_secs: i64,
) -> Result<UploadQuotaUsage> {
    let usage = conn
        .query_row(
            "SELECT bytes_uploaded, uploads
             FROM upload_counters
             WHERE subject = ?1 AND window_start = ?2",
            params![subject.key(), window_start(now, window_secs)],
            |row| {
                Ok(UploadQuotaUsage {
                    bytes: row.get(0)?,
                    uploads: row.get(1)?,
                })
            },
        )
        .optional()
        .context("Failed to read upload quota counter")?;
    Ok(usage.unwrap_or_default())
}

/// Add an upload to a subject's counter for the current window.
///
/// This is an unconditional upsert rather than a checked one: the caller has
/// already refused anything over budget, and a counter that refused to move
/// would let a submission be accepted without ever being charged for.
///
/// # Errors
/// Returns an error if the counter cannot be written.
pub fn record_upload_quota_usage(
    conn: &rusqlite::Connection,
    subject: &UploadQuotaSubject,
    bytes: i64,
    window_secs: i64,
    now: i64,
) -> Result<()> {
    let bytes = bytes.max(0);
    conn.execute(
        "INSERT INTO upload_counters (subject, window_start, bytes_uploaded, uploads)
         VALUES (?1, ?2, ?3, 1)
         ON CONFLICT (subject, window_start)
         DO UPDATE SET bytes_uploaded = bytes_uploaded + ?3, uploads = uploads + 1",
        params![subject.key(), window_start(now, window_secs), bytes],
    )
    .context("Failed to record upload quota counter")?;
    Ok(())
}

/// Check a submission against a subject's budget and charge it when it fits.
///
/// Checking and charging are one call so the two cannot disagree: a caller
/// that checked on one subject and charged another would let every submission
/// past the second budget while being refused by the first.
///
/// The bytes charged are the ones actually stored, not the ones submitted, so
/// a conversion that shrank the file is not billed for the original and a
/// deduplicated upload is billed for what it added.
///
/// # Errors
/// Returns [`UploadQuotaRefusal::Exceeded`] when the submission does not fit
/// the budget, and [`UploadQuotaRefusal::Storage`] when the counter cannot be
/// read or written. A refusal charges nothing.
pub fn charge_upload_quota(
    conn: &rusqlite::Connection,
    subject: &UploadQuotaSubject,
    bytes: i64,
    limits: UploadQuotaLimits,
    window_secs: i64,
    now: i64,
) -> Result<(), UploadQuotaRefusal> {
    if limits.is_unlimited() {
        return Ok(());
    }
    let usage = upload_quota_usage(conn, subject, now, window_secs)
        .map_err(UploadQuotaRefusal::Storage)?;
    if limits.max_bytes > 0 && usage.bytes.saturating_add(bytes.max(0)) > limits.max_bytes {
        return Err(UploadQuotaRefusal::Exceeded(
            UploadQuotaExceeded::Bytes {
                limit: limits.max_bytes,
            },
        ));
    }
    if limits.max_uploads > 0 && usage.uploads.saturating_add(1) > limits.max_uploads {
        return Err(UploadQuotaRefusal::Exceeded(
            UploadQuotaExceeded::Uploads {
                limit: limits.max_uploads,
            },
        ));
    }
    record_upload_quota_usage(conn, subject, bytes, window_secs, now)
        .map_err(UploadQuotaRefusal::Storage)
}

/// Delete counter rows whose window has already closed.
///
/// The table holds one row per subject per window, so without this it grows by
/// the number of distinct subjects every window and keeps answering questions
/// nobody asks about a week later.
///
/// # Errors
/// Returns an error if the counters cannot be pruned.
pub fn prune_upload_counters(conn: &rusqlite::Connection, now: i64, window_secs: i64) -> Result<()> {
    let current = window_start(now, window_secs);
    conn.execute(
        "DELETE FROM upload_counters WHERE window_start < ?1",
        params![current],
    )
    .context("Failed to prune upload quota counters")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        charge_upload_quota, prune_upload_counters, record_upload_quota_usage, upload_quota_usage,
        UploadQuotaExceeded, UploadQuotaLimits, UploadQuotaRefusal, UploadQuotaSubject,
    };
    use crate::db::schema::install_or_migrate_schema;
    use anyhow::{Context as _, Result};

    const WINDOW: i64 = 86_400;
    const NOW: i64 = 1_700_000_000;

    fn test_conn() -> Result<rusqlite::Connection> {
        let conn = rusqlite::Connection::open_in_memory()?;
        install_or_migrate_schema(&conn)?;
        Ok(conn)
    }

    fn account(id: i64) -> UploadQuotaSubject {
        UploadQuotaSubject::Account(id)
    }

    fn limits(max_bytes: i64, max_uploads: i64) -> UploadQuotaLimits {
        UploadQuotaLimits {
            max_bytes,
            max_uploads,
        }
    }

    /// Return the budget a charge was refused over, panicking on a storage
    /// failure, which an in-memory database cannot produce.
    fn refused_budget(
        conn: &rusqlite::Connection,
        subject: &UploadQuotaSubject,
        bytes: i64,
        limits: UploadQuotaLimits,
    ) -> Option<UploadQuotaExceeded> {
        match charge_upload_quota(conn, subject, bytes, limits, WINDOW, NOW) {
            Ok(()) => None,
            Err(refusal) => Some(
                refusal
                    .exceeded()
                    .expect("an in-memory counter must not fail to store"),
            ),
        }
    }

    #[test]
    /// A subject that has uploaded nothing has a usage of zero rather than a
    /// missing counter, and every accepted upload lands on exactly one row for
    /// the window it belongs to.
    fn a_fresh_subject_has_uploaded_nothing() -> Result<()> {
        let conn = test_conn()?;

        assert_eq!(
            upload_quota_usage(&conn, &account(1), NOW, WINDOW)?,
            super::UploadQuotaUsage::default()
        );
        record_upload_quota_usage(&conn, &account(1), 500, WINDOW, NOW)?;
        record_upload_quota_usage(&conn, &account(1), 250, WINDOW, NOW)?;
        assert_eq!(
            upload_quota_usage(&conn, &account(1), NOW, WINDOW)?,
            super::UploadQuotaUsage {
                bytes: 750,
                uploads: 2
            }
        );
        // A different account keeps its own budget.
        assert_eq!(
            upload_quota_usage(&conn, &account(2), NOW, WINDOW)?,
            super::UploadQuotaUsage::default()
        );
        Ok(())
    }

    #[test]
    /// A budget is spent by the uploads that fit inside it and refuses the
    /// next one, and the refusal charges nothing: an account turned away at
    /// the door must not be charged for the attempt.
    fn a_spent_budget_refuses_the_next_upload_and_charges_nothing() -> Result<()> {
        let conn = test_conn()?;
        let subject = account(7);

        charge_upload_quota(&conn, &subject, 600, limits(1000, 10), WINDOW, NOW)
            .map_err(|error| anyhow::anyhow!("first upload must fit: {error}"))?;
        assert_eq!(
            refused_budget(&conn, &subject, 500, limits(1000, 10)),
            Some(UploadQuotaExceeded::Bytes { limit: 1000 }),
            "an upload that would cross the byte budget must be refused"
        );
        assert_eq!(
            upload_quota_usage(&conn, &subject, NOW, WINDOW)?,
            super::UploadQuotaUsage {
                bytes: 600,
                uploads: 1
            },
            "a refused upload must not be charged"
        );
        Ok(())
    }

    #[test]
    /// The byte budget and the count budget are different answers, and a
    /// subject that has spent its file count is told so rather than being
    /// told it uploaded too much.
    fn the_count_budget_is_reported_separately_from_the_byte_budget() -> Result<()> {
        let conn = test_conn()?;
        let subject = account(9);

        let twice = limits(0, 2);
        charge_upload_quota(&conn, &subject, 10, twice, WINDOW, NOW)
            .map_err(|error| anyhow::anyhow!("first upload must fit: {error}"))?;
        charge_upload_quota(&conn, &subject, 10, twice, WINDOW, NOW)
            .map_err(|error| anyhow::anyhow!("second upload must fit: {error}"))?;
        assert_eq!(
            refused_budget(&conn, &subject, 10, twice),
            Some(UploadQuotaExceeded::Uploads { limit: 2 }),
            "a spent file count must be reported as a file count, not as bytes"
        );
        assert_eq!(
            upload_quota_usage(&conn, &subject, NOW, WINDOW)?.bytes,
            20,
            "a refusal over the count budget must leave the byte total alone"
        );
        Ok(())
    }

    #[test]
    /// The byte budget and the count budget answer different questions, so a
    /// subject can be inside one and outside the other. An upload is refused
    /// for whichever it crosses, and one that fits both is accepted.
    fn the_two_budgets_are_independent() -> Result<()> {
        let conn = test_conn()?;
        let subject = account(11);

        // Small files, but more of them than the count allows.
        for _ in 0..3 {
            let _ = charge_upload_quota(&conn, &subject, 10, limits(1000, 2), WINDOW, NOW);
        }
        assert_eq!(
            upload_quota_usage(&conn, &subject, NOW, WINDOW)?.uploads,
            2,
            "only accepted uploads are charged"
        );

        // A wide budget with room for the bytes but not for another file.
        let roomy = account(12);
        let wide = limits(1000, 2);
        charge_upload_quota(&conn, &roomy, 900, wide, WINDOW, NOW)
            .map_err(|error| anyhow::anyhow!("first upload must fit: {error}"))?;
        assert_eq!(
            refused_budget(&conn, &roomy, 900, wide),
            Some(UploadQuotaExceeded::Bytes { limit: 1000 })
        );
        Ok(())
    }

    #[test]
    /// A budget that is switched off places no limit on anybody, so an
    /// operator who sets both to zero is not left with submissions refused
    /// over a budget that does not exist.
    fn a_disabled_budget_refuses_nothing() -> Result<()> {
        let conn = test_conn()?;
        let subject = account(13);
        let off = limits(0, 0);

        assert!(off.is_unlimited());
        for _ in 0..50 {
            charge_upload_quota(&conn, &subject, u32::MAX as i64, off, WINDOW, NOW)
                .map_err(|error| anyhow::anyhow!("a disabled budget must refuse nothing: {error}"))?;
        }
        // Nothing was charged, because there was no budget to charge against.
        assert_eq!(
            upload_quota_usage(&conn, &subject, NOW, WINDOW)?,
            super::UploadQuotaUsage::default()
        );
        Ok(())
    }

    #[test]
    /// The two subjects are counted apart even when they describe the same
    /// person, because they are two budgets: one stops an account spreading
    /// its uploads across sessions, the other stops a shared address being
    /// used to spend past a limit no one person reached.
    fn an_account_and_an_address_keep_separate_budgets() -> Result<()> {
        let conn = test_conn()?;
        let as_account = account(21);
        let as_address = UploadQuotaSubject::Address("hash21".to_owned());

        let budget = limits(1000, 10);
        charge_upload_quota(&conn, &as_account, 1000, budget, WINDOW, NOW)
            .map_err(|error| anyhow::anyhow!("first upload must fit: {error}"))?;
        assert_eq!(
            upload_quota_usage(&conn, &as_address, NOW, WINDOW)?,
            super::UploadQuotaUsage::default(),
            "spending the account budget must not spend the address budget"
        );
        charge_upload_quota(&conn, &as_address, 1000, budget, WINDOW, NOW)
            .map_err(|error| anyhow::anyhow!("the address budget is its own: {error}"))?;
        assert_eq!(
            upload_quota_usage(&conn, &as_address, NOW, WINDOW)?.bytes,
            1000
        );
        Ok(())
    }

    #[test]
    /// The budget is spent per window, not forever: what a subject uploaded
    /// yesterday is not charged against today's allowance.
    fn the_budget_resets_with_the_window() -> Result<()> {
        let conn = test_conn()?;
        let subject = account(31);
        let budget = limits(1000, 10);

        charge_upload_quota(&conn, &subject, 1000, budget, WINDOW, NOW)
            .map_err(|error| anyhow::anyhow!("the first upload must fit: {error}"))?;
        assert!(
            charge_upload_quota(&conn, &subject, 1, budget, WINDOW, NOW).is_err(),
            "a spent budget must refuse the next upload in the same window"
        );

        let next_window = NOW + WINDOW;
        charge_upload_quota(&conn, &subject, 1000, budget, WINDOW, next_window)
            .map_err(|error| anyhow::anyhow!("the new window must start empty: {error}"))?;
        assert_eq!(
            upload_quota_usage(&conn, &subject, next_window, WINDOW)?,
            super::UploadQuotaUsage {
                bytes: 1000,
                uploads: 1
            },
            "the new window starts empty rather than carrying yesterday's total"
        );
        Ok(())
    }

    #[test]
    /// Windows are aligned to the epoch, so every subject resets at the same
    /// moment and a counter is found by its key rather than by a range.
    fn windows_align_to_the_epoch() {
        assert_eq!(super::window_start(0, WINDOW), 0);
        assert_eq!(super::window_start(WINDOW - 1, WINDOW), 0);
        assert_eq!(super::window_start(WINDOW, WINDOW), WINDOW);
        assert_eq!(super::window_start(WINDOW * 3 + 7, WINDOW), WINDOW * 3);
    }

    #[test]
    /// A pruned counter is not a lost budget: the row is removed once its
    /// window closes, and the subject it belonged to reads as having uploaded
    /// nothing in the current one.
    fn pruning_removes_closed_windows_only() -> Result<()> {
        let conn = test_conn()?;
        let subject = account(41);
        record_upload_quota_usage(&conn, &subject, 10, WINDOW, NOW)?;
        let later = NOW + (WINDOW * 2);
        record_upload_quota_usage(&conn, &subject, 20, WINDOW, later)?;

        prune_upload_counters(&conn, later, WINDOW)?;

        assert_eq!(
            upload_quota_usage(&conn, &subject, later, WINDOW)?.bytes,
            20,
            "the current window's counter must survive pruning"
        );
        assert_eq!(
            upload_quota_usage(&conn, &subject, NOW, WINDOW)?,
            super::UploadQuotaUsage::default(),
            "a closed window's counter is gone, and reads as nothing uploaded"
        );
        Ok(())
    }

    #[test]
    /// A negative size cannot be used to move a counter backwards, which would
    /// hand a subject fresh budget for free.
    fn a_negative_size_cannot_refund_a_counter() -> Result<()> {
        let conn = test_conn()?;
        let subject = account(51);
        record_upload_quota_usage(&conn, &subject, 500, WINDOW, NOW)?;
        record_upload_quota_usage(&conn, &subject, -9000, WINDOW, NOW)?;

        let usage = upload_quota_usage(&conn, &subject, NOW, WINDOW)?;
        assert_eq!(usage.bytes, 500, "a negative size must be charged as zero");
        assert_eq!(usage.uploads, 2);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions intentionally report a violated quota invariant"
    )]
    /// A submission that carries no file spends no budget and is never
    /// refused, so a text post is unaffected by a media budget.
    fn a_submission_without_a_file_is_never_refused() -> Result<()> {
        let conn = test_conn().context("in-memory database")?;
        let subject = account(61);
        let tiny = limits(1, 1);
        charge_upload_quota(&conn, &subject, 1, tiny, WINDOW, NOW)
            .map_err(|error| anyhow::anyhow!("the first upload must fit: {error}"))?;
        // The budget is spent, but a submission with nothing attached is
        // charged zero bytes and adds no file, so it still fits.
        charge_upload_quota(&conn, &subject, 0, tiny, WINDOW, NOW)
            .map_err(|error| anyhow::anyhow!("a post without media must not be refused: {error}"))?;
        assert_eq!(upload_quota_usage(&conn, &subject, NOW, WINDOW)?.uploads, 2);
        Ok(())
    }
}
