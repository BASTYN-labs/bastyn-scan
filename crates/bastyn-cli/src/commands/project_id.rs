//! `bastyn project-id` — print the project ID that scans report under.

use std::io::Write as _;

use anyhow::{Context as _, bail};
use bastyn_core::reporting::project_id::{self, IdSource, Inputs, Resolution};
use bastyn_core::reporting::state;

use crate::cli::ProjectIdArgs;

/// Said when the project has no remote and no stored ID exists yet.
const NOT_CREATED: &str = "no project ID yet: this project has no git remote, so one is created on the first scan that reports";

/// Run the `project-id` subcommand.
///
/// Resolves without creating the local ID, so this command never writes a
/// file and never uses the network.
pub(crate) fn run(args: &ProjectIdArgs) -> anyhow::Result<()> {
    let env = |name: &str| std::env::var_os(name);
    let state_dir = state::state_dir(&env);
    let resolution = project_id::resolve(&Inputs {
        scan_root: &args.path,
        env: &env,
        state_dir: state_dir.as_deref(),
        create_local: false,
    });

    let text = match resolution {
        Resolution::Resolved(project) => {
            let mut text = format!("{}\n", project.id);
            if args.explain {
                let derivation = match project.source {
                    IdSource::Remote => format!("sha256({})", project.explanation.hashed),
                    IdSource::Local => {
                        "sha256(\"bastyn-project-v1-local:\" + stored random value)".to_owned()
                    }
                };
                for line in [
                    format!("source: {}", project.source.as_str()),
                    format!("hashed: {}", project.explanation.hashed),
                    format!("origin: {}", project.explanation.origin),
                    format!("derivation: {derivation}"),
                ] {
                    text.push_str(&line);
                    text.push('\n');
                }
            }
            text
        }
        Resolution::LocalNotCreated => format!("{NOT_CREATED}\n"),
        Resolution::Unavailable(reason) => bail!("no project ID: {reason}"),
    };

    std::io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .context("could not write to stdout")
}
