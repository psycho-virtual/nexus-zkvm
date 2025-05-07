use std::sync::Once;
use tracing_subscriber::{fmt, EnvFilter, prelude::*};

static START: Once = Once::new();

/// Call this at the start of every `#[test]`.  
/// The first call installs a subscriber; later calls are no-ops.
pub fn init() {
    START.call_once(|| {
        // Include debug logs for both hypernova::nimfs and hypernova::sequential
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("warn,hypernova::nimfs=debug,nexus-nova::hypernova::sequential=debug"));
        
        let _ = tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_test_writer() // prints under `cargo test -v` or `--nocapture`
                    .with_span_events(fmt::format::FmtSpan::ENTER | fmt::format::FmtSpan::CLOSE) // Show spans
            )
            .with(filter)
            .try_init();
    });
} 