use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
use tokio::sync::broadcast;
use tracing_subscriber::Layer;

type LogReload = dyn Fn(&str) -> Result<(), String> + Send + Sync;

/// Restore the actual logging state captured before a tentative PATCH.
/// The action must restore the filter and any associated facade max level.
pub type LogRollbackAction = Box<dyn FnOnce() -> Result<(), String> + Send + 'static>;
type LogSnapshot = dyn Fn() -> Result<LogRollbackAction, String> + Send + Sync;

struct LogReloader {
    reload: Box<LogReload>,
    snapshot: Option<Box<LogSnapshot>>,
}

static LOG_RELOAD: std::sync::OnceLock<LogReloader> = std::sync::OnceLock::new();

/// Install a legacy reloader for ordinary, single-stage log-level updates.
/// Multi-stage TUN PATCHes also need a snapshot; embedders can install the
/// rollback-aware variant below without changing this existing API.
pub fn install_log_reloader<F>(reload: F)
where
    F: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
{
    let _ = LOG_RELOAD.set(LogReloader {
        reload: Box::new(reload),
        snapshot: None,
    });
}

/// Install a reloader together with a snapshot of its current actual state.
/// Snapshotting must not modify logging. A returned action restores that
/// exact state, including an environment-selected filter, without consulting
/// the raw configuration document. Installation is atomic and first-wins.
pub fn install_log_reloader_with_rollback<F, S>(reload: F, snapshot: S)
where
    F: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
    S: Fn() -> Result<LogRollbackAction, String> + Send + Sync + 'static,
{
    let _ = LOG_RELOAD.set(LogReloader {
        reload: Box::new(reload),
        snapshot: Some(Box::new(snapshot)),
    });
}

pub fn reload_log_level(level: &str) -> Result<(), String> {
    match LOG_RELOAD.get() {
        Some(reloader) => (reloader.reload)(level),
        None => Ok(()),
    }
}

/// Restore a tentative logging update unless the complete PATCH commits.
#[must_use = "dropping the token restores the previous actual log filter"]
pub(crate) struct LogLevelRollback {
    restore: Option<LogRollbackAction>,
}

impl LogLevelRollback {
    /// Keep the new logging state after every fallible PATCH step succeeds.
    pub(crate) fn commit(mut self) {
        self.restore = None;
    }
}

impl Drop for LogLevelRollback {
    fn drop(&mut self) {
        if let Some(restore) = self.restore.take() {
            if let Err(error) = restore() {
                tracing::error!(%error, "failed to restore the previous log filter");
            }
        }
    }
}

/// Apply logging before a fallible TUN transition and retain its exact undo.
/// A legacy embedder without a snapshot fails before either step changes
/// state. No installed reloader is a no-op, like reload_log_level itself.
pub(crate) fn begin_log_level(level: &str) -> Result<LogLevelRollback, String> {
    let Some(reloader) = LOG_RELOAD.get() else {
        return Ok(LogLevelRollback { restore: None });
    };
    let snapshot = reloader.snapshot.as_ref().ok_or_else(|| {
        "the installed log reloader has no rollback snapshot for a TUN PATCH".to_owned()
    })?;
    let rollback = LogLevelRollback {
        restore: Some(snapshot()?),
    };
    // Construct the token first: even a callback that partially mutates
    // logging before returning an error is restored by the error path.
    (reloader.reload)(level)?;
    Ok(rollback)
}

/// The `log-level` values meow accepts (mihomo names — `warning`/`silent`
/// are normalized to `warn`/`off` by the filter's caller). Shared by the
/// PATCH whitelist and the startup `log-level:` application so a typo can
/// never reach `EnvFilter::new`, which would parse a bare word as a
/// `target=TRACE` directive and blackhole all logging instead of erroring
/// (issue #729).
pub fn is_valid_log_level(level: &str) -> bool {
    matches!(
        level.to_ascii_lowercase().as_str(),
        "debug" | "info" | "warning" | "warn" | "error" | "silent"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Silent,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Silent => "silent",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogMessage {
    pub level: LogLevel,
    pub payload: String,
    pub time: time::OffsetDateTime,
}

impl Serialize for LogMessage {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_struct("LogMessage", 3)?;
        m.serialize_field("type", self.level.as_str())?;
        m.serialize_field("payload", &self.payload)?;
        let ts = self
            .time
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        m.serialize_field("time", &ts)?;
        m.end()
    }
}

pub struct LogBroadcastLayer {
    pub tx: broadcast::Sender<LogMessage>,
}

impl<S: tracing::Subscriber> Layer<S> for LogBroadcastLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // The broadcast sender exists for the process lifetime, but most
        // deployments have no active /logs consumer. Avoid formatting fields,
        // reading the clock, and constructing a heap-backed message when there
        // is nobody to receive it.
        if self.tx.receiver_count() == 0 {
            return;
        }
        let level = match *event.metadata().level() {
            tracing::Level::TRACE | tracing::Level::DEBUG => LogLevel::Debug,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::WARN => LogLevel::Warning,
            tracing::Level::ERROR => LogLevel::Error,
        };
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let msg = LogMessage {
            level,
            payload: visitor.0,
            time: time::OffsetDateTime::now_utc(),
        };
        // Non-blocking; Err = no subscribers or channel full — both acceptable.
        let _ = self.tx.send(msg);
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
}

pub fn parse_log_level(s: &str) -> LogLevel {
    match s.to_ascii_lowercase().as_str() {
        "debug" => LogLevel::Debug,
        "warning" | "warn" => LogLevel::Warning,
        "error" => LogLevel::Error,
        "silent" => LogLevel::Silent,
        // "info" and any unrecognised value default to Info.
        _ => LogLevel::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::subscriber;
    use tracing_subscriber::prelude::*;

    #[test]
    fn log_level_str_round_trip_via_parse() {
        for (s, lvl) in [
            ("debug", LogLevel::Debug),
            ("info", LogLevel::Info),
            ("warning", LogLevel::Warning),
            ("error", LogLevel::Error),
            ("silent", LogLevel::Silent),
        ] {
            assert_eq!(parse_log_level(s), lvl);
            assert_eq!(lvl.as_str(), s);
        }
    }

    #[test]
    fn parse_log_level_accepts_warn_alias() {
        assert_eq!(parse_log_level("warn"), LogLevel::Warning);
        assert_eq!(parse_log_level("WARN"), LogLevel::Warning);
    }

    #[test]
    fn parse_log_level_is_case_insensitive() {
        assert_eq!(parse_log_level("DEBUG"), LogLevel::Debug);
        assert_eq!(parse_log_level("Info"), LogLevel::Info);
        assert_eq!(parse_log_level("Error"), LogLevel::Error);
    }

    #[test]
    fn parse_log_level_unknown_input_defaults_to_info() {
        // Documented behaviour: an unrecognised level → fall back to Info
        // rather than rejecting the request.
        assert_eq!(parse_log_level(""), LogLevel::Info);
        assert_eq!(parse_log_level("nonsense"), LogLevel::Info);
        assert_eq!(parse_log_level("trace"), LogLevel::Info);
    }

    #[test]
    fn is_valid_log_level_whitelists_only_levels() {
        for s in ["debug", "info", "warning", "warn", "error", "silent"] {
            assert!(is_valid_log_level(s), "{s}");
            assert!(is_valid_log_level(&s.to_uppercase()), "{s} upper");
        }
        // A bare word must never reach EnvFilter — it parses as a
        // `target=TRACE` directive and blackholes all logging (#729).
        for s in ["debg", "trace", "", "meow_tunnel=debug", " a "] {
            assert!(!is_valid_log_level(s), "{s}");
        }
    }

    #[test]
    fn log_level_ord_matches_severity_increasing() {
        // The WS handler filters with `level >= request_level`. The enum
        // ordering must therefore be Debug < Info < Warning < Error < Silent
        // (where Silent is the strictest filter — nothing passes).
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warning);
        assert!(LogLevel::Warning < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Silent);
    }

    #[test]
    fn log_message_serializes_three_fields() {
        // 2026-01-02 03:04:05 UTC = 1767322945 seconds since unix epoch.
        let ts = time::OffsetDateTime::from_unix_timestamp(1_767_322_945).unwrap();
        let msg = LogMessage {
            level: LogLevel::Warning,
            payload: "alerts: thing happened".into(),
            time: ts,
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "warning");
        assert_eq!(json["payload"], "alerts: thing happened");
        assert_eq!(json["time"], "2026-01-02T03:02:25Z");
    }

    #[test]
    fn layer_forwards_string_message_event() {
        let (tx, mut rx) = broadcast::channel(8);
        let layer = LogBroadcastLayer { tx };
        let registry = tracing_subscriber::registry().with(layer);
        subscriber::with_default(registry, || {
            tracing::warn!("hello-world");
        });
        let got = rx.try_recv().expect("event must be forwarded");
        assert_eq!(got.level, LogLevel::Warning);
        assert!(
            got.payload.contains("hello-world"),
            "payload: {}",
            got.payload
        );
    }

    #[test]
    fn layer_maps_tracing_levels_to_log_levels() {
        let (tx, mut rx) = broadcast::channel(16);
        let layer = LogBroadcastLayer { tx };
        let registry = tracing_subscriber::registry().with(layer);
        subscriber::with_default(registry, || {
            tracing::error!("e");
            tracing::warn!("w");
            tracing::info!("i");
            tracing::debug!("d"); // collapses to Debug
            tracing::trace!("t"); // collapses to Debug
        });
        let levels: Vec<LogLevel> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|m| m.level)
            .collect();
        // Trace+debug both map to Debug; default filter may drop them at the
        // subscriber level, so accept either {Error, Warning, Info} only or
        // the full set.
        assert!(levels.starts_with(&[LogLevel::Error, LogLevel::Warning, LogLevel::Info]));
        for extra in &levels[3..] {
            assert_eq!(*extra, LogLevel::Debug);
        }
    }

    #[test]
    fn layer_skips_event_recording_with_no_subscribers() {
        struct PanicOnFormat;
        impl std::fmt::Debug for PanicOnFormat {
            fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("event fields must not be formatted without log subscribers");
            }
        }

        let (tx, rx) = broadcast::channel(1);
        drop(rx);
        let layer = LogBroadcastLayer { tx };
        let registry = tracing_subscriber::registry().with(layer);
        subscriber::with_default(registry, || {
            tracing::info!(message = ?PanicOnFormat);
        });
    }
}
