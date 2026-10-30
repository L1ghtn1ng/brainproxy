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

/// The release asset for this platform, as `release` names it. The desktop app on
/// Windows comes as an MSI (installed for all users under Program Files) or a
/// per-user setup.exe, and on Linux as a .deb or an AppImage: the same kind as the
/// running copy is chosen. macOS has no separate command-line download (the app
/// includes it).
pub fn find_asset(release: &Release, kind: Kind) -> Option<&Asset> {
    find(release, &name(this_platform(kind)?, &release.version))
}

/// The file name this platform's download has in a release of `version`.
pub fn asset_name(kind: Kind, version: &str) -> Option<String> {
    Some(name(this_platform(kind)?, version))
}

fn this_platform(kind: Kind) -> Option<(&'static str, String)> {
    let exe = std::env::current_exe().unwrap_or_default();
    platform_asset(
        std::env::consts::OS,
        std::env::consts::ARCH,
        kind,
        exe.to_string_lossy().to_ascii_lowercase().contains("program files"),
        std::env::var_os("APPIMAGE").is_some(),
    )
}

/// The download for a platform, split around where the version goes: the product
/// (`brainproxy` or `brainproxy-gui`) and the rest (`linux-x86_64.deb`).
fn platform_asset(os: &str, arch: &str, kind: Kind, msi: bool, appimage: bool) -> Option<(&'static str, String)> {
    let arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "arm64",
        _ => return None,
    };
    let (gui, cli) = ("brainproxy-gui", "brainproxy");
    Some(match (os, kind) {
        ("macos", _) => (gui, format!("macos-{arch}.dmg")),
        ("windows", Kind::Gui) if msi => (gui, format!("windows-{arch}.msi")),
        ("windows", Kind::Gui) => (gui, format!("windows-{arch}-setup.exe")),
        ("windows", Kind::Cli) => (cli, format!("windows-{arch}.exe")),
        ("linux", Kind::Gui) if appimage => (gui, format!("linux-{arch}.AppImage")),
        ("linux", Kind::Gui) => (gui, format!("linux-{arch}.deb")),
        ("linux", Kind::Cli) => (cli, format!("linux-{arch}")),
        _ => return None,
    })
}

/// The name a download has in a release of `version`
/// (`brainproxy-gui-0.3.9-linux-x86_64.deb`).
fn name((product, rest): (&str, String), version: &str) -> String {
    format!("{product}-{version}-{rest}")
}

fn find<'a>(release: &'a Release, name: &str) -> Option<&'a Asset> {
    release.assets.iter().find(|a| a.name == name)
}

/// Whether a download is a program to run as is: the command line (no extension
/// after the arch) or the AppImage, rather than an installer that is opened.
#[cfg(any(unix, test))]
fn executable(name: &str) -> bool {
    name.ends_with(".AppImage") || !name.rsplit('-').next().unwrap_or_default().contains('.')
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
    if executable(&asset.name) {
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
        let gui = asset_name(Kind::Gui, "0.3.9").unwrap();
        assert!(gui.starts_with("brainproxy-gui-0.3.9-"), "{gui}");
        let cli = asset_name(Kind::Cli, "0.3.9").unwrap();
        assert!(cli.starts_with("brainproxy-"), "{cli}");
        if cfg!(target_os = "macos") {
            assert_eq!(gui, cli);
        }
    }

    #[test]
    fn asset_names_per_platform() {
        let name =
            |os, arch, kind, msi, appimage| name(platform_asset(os, arch, kind, msi, appimage).unwrap(), "0.3.9");
        use Kind::*;
        assert_eq!(name("linux", "x86_64", Cli, false, false), "brainproxy-0.3.9-linux-x86_64");
        assert_eq!(name("linux", "aarch64", Cli, false, false), "brainproxy-0.3.9-linux-arm64");
        assert_eq!(name("linux", "x86_64", Gui, false, false), "brainproxy-gui-0.3.9-linux-x86_64.deb");
        assert_eq!(name("linux", "x86_64", Gui, false, true), "brainproxy-gui-0.3.9-linux-x86_64.AppImage");
        assert_eq!(name("windows", "x86_64", Cli, false, false), "brainproxy-0.3.9-windows-x86_64.exe");
        assert_eq!(name("windows", "x86_64", Gui, false, false), "brainproxy-gui-0.3.9-windows-x86_64-setup.exe");
        assert_eq!(name("windows", "x86_64", Gui, true, false), "brainproxy-gui-0.3.9-windows-x86_64.msi");
        assert_eq!(name("macos", "aarch64", Gui, false, false), "brainproxy-gui-0.3.9-macos-arm64.dmg");
        assert_eq!(name("macos", "aarch64", Cli, false, false), "brainproxy-gui-0.3.9-macos-arm64.dmg");
        assert!(platform_asset("linux", "riscv64", Cli, false, false).is_none());
        assert!(platform_asset("freebsd", "x86_64", Cli, false, false).is_none());
    }

    fn release(version: &str, assets: &[&str]) -> Release {
        Release {
            tag: format!("v{version}"),
            version: version.into(),
            url: String::new(),
            published_at: String::new(),
            notes: String::new(),
            assets: assets
                .iter()
                .map(|n| Asset { name: n.to_string(), size: 1, url: format!("https://x/{n}") })
                .collect(),
        }
    }

    #[test]
    fn picks_the_versioned_name() {
        let deb = |v| name(platform_asset("linux", "x86_64", Kind::Gui, false, false).unwrap(), v);
        let cli = |v| name(platform_asset("linux", "x86_64", Kind::Cli, false, false).unwrap(), v);
        let new = release(
            "0.3.9",
            &[
                "brainproxy-0.3.9-linux-x86_64",
                "brainproxy-0.3.9-linux-x86_64.sha256",
                "brainproxy-gui-0.3.9-linux-x86_64.deb",
                "brainproxy-gui-0.3.9-linux-x86_64.deb.sha256",
                "SHA256SUMS",
            ],
        );
        assert_eq!(find(&new, &deb("0.3.9")).unwrap().name, "brainproxy-gui-0.3.9-linux-x86_64.deb");
        assert_eq!(find(&new, &cli("0.3.9")).unwrap().name, "brainproxy-0.3.9-linux-x86_64");
        // An unversioned name (releases up to 0.3.8) is not looked for.
        let old = release("0.3.8", &["brainproxy-linux-x86_64", "brainproxy-gui-linux-x86_64.deb"]);
        assert!(find(&old, &cli("0.3.8")).is_none());
        // A file for another version, or another platform, is not this release's download.
        let other = release("0.4.0", &["brainproxy-0.3.9-linux-x86_64", "brainproxy-0.4.0-linux-arm64"]);
        assert!(find(&other, &cli("0.4.0")).is_none());
    }

    #[test]
    fn executable_downloads() {
        assert!(executable("brainproxy-0.3.9-linux-x86_64"));
        assert!(executable("brainproxy-linux-arm64"));
        assert!(executable("brainproxy-gui-0.3.9-linux-x86_64.AppImage"));
        assert!(!executable("brainproxy-gui-0.3.9-linux-x86_64.deb"));
        assert!(!executable("brainproxy-gui-0.3.9-macos-arm64.dmg"));
        assert!(!executable("brainproxy-0.3.9-windows-x86_64.exe"));
        assert!(!executable("brainproxy-gui-0.3.9-windows-x86_64-setup.exe"));
        assert!(!executable("brainproxy-0.3.9-linux-x86_64.tar.gz"));
    }
}
