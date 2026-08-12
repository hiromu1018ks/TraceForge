//! `traceforge timeline <case>` command（製品 §12・T7-023）。
//!
//! Case JSON / JSONL から Event を読み込み、Timeline 形式で表示・filter する。
//! Timeline 順（規範 §6.3）へ整列し、filter 条件（時刻範囲・Event type・hostname）を適用する。

use std::path::Path;

use tf_core::error::ExitCode;
use tf_export::text;
use tf_store::timeline::{TimelineFilter, TimelineKey};

use crate::args::TimelineArgs;
use crate::commands::CommandResult;
use crate::runtime::{RunContext, read_case_from_path};

/// `timeline` command の実行。
pub fn run(args: &TimelineArgs, ctx: &mut RunContext) -> CommandResult {
    let case_path = Path::new(&args.case);
    let mut data = match read_case_from_path(case_path) {
        Ok(d) => d,
        Err(e) => {
            return CommandResult::err(e.exit_code(), e.to_string());
        }
    };

    // filter 構築。
    let filter = TimelineFilter {
        utc_from: args.utc_from.clone(),
        utc_to: args.utc_to.clone(),
        event_types: args.event_types.clone(),
        hostnames: args.hostnames.clone(),
    };

    // Timeline 順で sort し、filter を適用。
    let mut filtered_events: Vec<tf_core::event::Event> = Vec::new();
    for ev in &data.events {
        let key = TimelineKey::from_event(ev);
        if filter.matches(&key, ev) {
            filtered_events.push(ev.clone());
        }
    }
    data.events = filtered_events;

    // Text 形式で stdout へ。
    let mut buf: Vec<u8> = Vec::new();
    if let Err(e) = text::write_text(&data, &mut buf) {
        return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string());
    }
    let stdout = String::from_utf8_lossy(&buf).into_owned();

    let exit_code = if data.issues.is_empty() {
        ExitCode::Success
    } else {
        ctx.log(format!("warning: {} 件の Issue がある", data.issues.len()));
        ExitCode::CaseWithWarnings
    };

    CommandResult {
        exit_code,
        stdout,
        stderr: String::new(),
    }
}
