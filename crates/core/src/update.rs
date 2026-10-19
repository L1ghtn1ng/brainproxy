//! Checks for, and downloads, newer brainproxy releases from GitHub (`update`).
//! Downloads are verified against the `.sha256` file published with each asset.
//! Nothing is installed: the installer or binary is saved for the user to run.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::fetch::{sha256_hex, GitHub};

pub const REPO: &str = "r4nd0mth1ngs/brainproxy";

/// The version of this build.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// Largest asset `download` accepts (the HTTP client's response limit); bigger
/// ones (the AppImage) are fetched from the release page.
pub const MAX_ASSET: u64 = crate::http::wire::MAX_BODY as u64;

#[derive(Debug, Clone, Serialize)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Release {
    pub tag: String,
    pub version: String,
    pub url: String,
    pub published_at: String,
    pub notes: String,
    #[serde(skip)]
    pub assets: Vec<Asset>,
}

/// Which download fits this machine: the desktop app, or the command line alone.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Gui,
    Cli,
}

/// The latest published release.
pub async fn latest() -> Result<Release> {
    let gh = GitHub::releases()?;
    let body =
        gh.get(&format!("https://api.github.com/repos/{REPO}/releases/latest"), "application/vnd.github+json").await?;
    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| Error::Protocol(format!("release: {e}")))?;
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    let tag = s("tag_name");
    if tag.is_empty() {
        return Err(Error::Protocol("release without a tag".into()));
    }
    let assets = v["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| {
            Some(Asset {
                name: a["name"].as_str()?.to_string(),
                size: a["size"].as_u64().unwrap_or(0),
                url: a["browser_download_url"].as_str()?.to_string(),
            })
        })
        .collect();
    Ok(Release {
        version: tag.trim_start_matches('v').to_string(),
        tag,
        url: s("html_url"),
        published_at: s("published_at"),
        notes: s("body"),
        assets,
    })
}

/// Whether `latest` is a higher version than `current` ("1.2.3", numeric parts).
pub fn newer(latest: &str, current: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v').split(['.', '-', '+']).take(3).map(|p| p.parse().unwrap_or(0)).collect()
    };
    parts(latest) > parts(current)
}

/// The release asset for this platform. The desktop app on Windows comes as an MSI
/// (installed for all users under Program Files) or a per-user setup.exe, and on
/// Linux as a .deb or an AppImage: the same kind as the running copy is chosen.
/// macOS has no separate command-line download (the app includes it).
pub fn asset_name(kind: Kind) -> Option<String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "arm64",
        _ => return None,
    };
    let exe = std::env::current_exe().unwrap_or_default();
    Some(match (std::env::consts::OS, kind) {
        ("macos", _) => format!("brainproxy-gui-macos-{arch}.dmg"),
        ("windows", Kind::Gui) if exe.to_string_lossy().to_ascii_lowercase().contains("program files") => {
            format!("brainproxy-gui-windows-{arch}.msi")
        }
        ("windows", Kind::Gui) => format!("brainproxy-gui-windows-{arch}-setup.exe"),
        ("windows", Kind::Cli) => format!("brainproxy-windows-{arch}.exe"),
        ("linux", Kind::Gui) if std::env::var_os("APPIMAGE").is_some() => {
            format!("brainproxy-gui-linux-{arch}.AppImage")
        }
        ("linux", Kind::Gui) => format!("brainproxy-gui-linux-{arch}.deb"),
        ("linux", Kind::Cli) => format!("brainproxy-linux-{arch}"),
        _ => return None,
    })
}

/// The user's Downloads folder, if there is one.
pub fn downloads_dir() -> Option<PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })?;
    Some(Path::new(&home).join("Downloads")).filter(|d| d.is_dir())
}

/// Downloads `asset` into `dir`, checks it against its published sha256, and
/// returns the saved path and the digest. An existing file of that name is replaced
/// only once the new one is verified.
pub async fn download(release: &Release, asset: &Asset, dir: &Path) -> Result<(PathBuf, String)> {
    if asset.size > MAX_ASSET {
        return Err(Error::InvalidInput(format!(
            "{} is {} MiB, over the {} MiB download limit; download it from {}",
            asset.name,
            asset.size >> 20,
            MAX_ASSET >> 20,
            release.url
        )));
    }
    let sums = release
        .assets
        .iter()
        .find(|a| a.name == format!("{}.sha256", asset.name))
        .ok_or_else(|| Error::NotFound(format!("{}.sha256 in release {}", asset.name, release.tag)))?;
    let gh = GitHub::releases()?;
    let want = String::from_utf8_lossy(&gh.get(&sums.url, "application/octet-stream").await?)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let data = gh.get(&asset.url, "application/octet-stream").await?;
    let got = sha256_hex(&data);
    if got != want {
        return Err(Error::Protocol(format!("{}: sha256 is {got}, the release says {want}", asset.name)));
    }
    std::fs::create_dir_all(dir)?;
    let path = dir.join(&asset.name);
    let part = dir.join(format!("{}.part", asset.name));
    std::fs::write(&part, &data)?;
    #[cfg(unix)]
    if !asset.name.contains('.') {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&part, &path)?;
    Ok((path, got))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(newer("v0.3.1", "0.3.0"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "0.99.0"));
        assert!(!newer("v0.3.0", "0.3.0"));
        assert!(!newer("0.2.9", "0.3.0"));
        assert!(!newer("garbage", "0.3.0"));
    }

    #[test]
    fn asset_for_this_platform() {
        let gui = asset_name(Kind::Gui).unwrap();
        assert!(gui.starts_with("brainproxy-gui-"), "{gui}");
        let cli = asset_name(Kind::Cli).unwrap();
        assert!(cli.starts_with("brainproxy-"), "{cli}");
        if cfg!(target_os = "macos") {
            assert_eq!(gui, cli);
        }
    }
}
