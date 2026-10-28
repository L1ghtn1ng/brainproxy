//! `update check|download`: newer brainproxy releases from GitHub.

use std::path::PathBuf;

use brainproxy_core::update::{self, Kind, Release};
use brainproxy_core::Error;
use clap::{Subcommand, ValueEnum};
use serde_json::json;

use crate::output::Out;

#[derive(Subcommand)]
pub enum UpdateCmd {
    /// Ask GitHub for the latest release and whether it is newer than this one.
    Check {
        /// Which download to report: the desktop app or the command line alone.
        #[arg(long, value_enum, default_value_t = KindArg::Cli)]
        kind: KindArg,
    },
    /// Download the latest release's installer or binary for this machine, checked
    /// against its published sha256. It is saved, not installed: run it yourself.
    Download {
        #[arg(long, value_enum, default_value_t = KindArg::Cli)]
        kind: KindArg,
        /// Folder to save to (default: your Downloads folder, else the current one).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum KindArg {
    Cli,
    Gui,
}

pub fn update(cmd: UpdateCmd, out: &Out) -> Result<(), Error> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let release = rt.block_on(update::latest())?;
    match cmd {
        UpdateCmd::Check { kind } => {
            let v = describe(&release, kind);
            out.ok(v.clone(), || {
                if v["update_available"] == true {
                    format!(
                        "brainproxy {} is available (this is {}): {}\nbrainproxy update download{}",
                        release.version,
                        update::CURRENT,
                        release.url,
                        if matches!(kind, KindArg::Gui) { " --kind gui" } else { "" }
                    )
                } else {
                    format!("brainproxy {} is the latest release", update::CURRENT)
                }
            });
        }
        UpdateCmd::Download { kind, dir } => {
            let name = update::asset_name(kind.into(), &release.version)
                .ok_or_else(|| Error::NotFound(format!("a release download for this platform; see {}", release.url)))?;
            let asset = update::find_asset(&release, kind.into())
                .ok_or_else(|| Error::NotFound(format!("{name} in release {}; see {}", release.tag, release.url)))?;
            let dir = dir.or_else(update::downloads_dir).unwrap_or_else(|| PathBuf::from("."));
            let (path, sha256) = rt.block_on(update::download(&release, asset, &dir))?;
            let mut v = describe(&release, kind);
            v["path"] = json!(path);
            v["sha256"] = json!(sha256);
            out.ok(v, || format!("saved brainproxy {} to {} (sha256 verified)", release.version, path.display()));
        }
    }
    Ok(())
}

fn describe(release: &Release, kind: KindArg) -> serde_json::Value {
    let asset = update::find_asset(release, kind.into());
    json!({
        "current": update::CURRENT,
        "latest": release.version,
        "update_available": update::newer(&release.version, update::CURRENT),
        "release": release,
        "asset": asset,
    })
}

impl From<KindArg> for Kind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::Cli => Kind::Cli,
            KindArg::Gui => Kind::Gui,
        }
    }
}
