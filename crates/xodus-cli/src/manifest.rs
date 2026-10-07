//! Parses `MicrosoftGame.config`, the GDK package manifest that lists a
//! title's executables. Extracted packages ship this file unencrypted
//! alongside the encrypted content, so it can be read directly.
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Game {
    #[serde(rename = "ExecutableList")]
    executable_list: ExecutableList,
}

#[derive(Debug, Deserialize)]
struct ExecutableList {
    #[serde(rename = "Executable", default)]
    executable: Vec<Executable>,
}

#[derive(Debug, Deserialize)]
struct Executable {
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "@TargetDeviceFamily")]
    target_device_family: String,
    #[serde(rename = "@IsDevOnly", default)]
    is_dev_only: bool,
}

/// Finds `MicrosoftGame.config` in `dir` (matched case-insensitively, since
/// packages on disk vary in casing) and returns the name of the executable
/// targeting the "PC" device family - the real main executable for a
/// Windows.Desktop package, per the manifest itself, rather than a guess.
pub fn find_pc_executable(dir: &Path) -> Option<String> {
    let manifest_path = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok())
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case("MicrosoftGame.config")
        })?
        .path();
    let xml = std::fs::read_to_string(manifest_path).ok()?;
    parse_pc_executable(&xml)
}

fn parse_pc_executable(xml: &str) -> Option<String> {
    let game: Game = quick_xml::de::from_str(xml).ok()?;
    game.executable_list
        .executable
        .into_iter()
        .find(|exe| exe.target_device_family.eq_ignore_ascii_case("PC") && !exe.is_dev_only)
        .map(|exe| exe.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real MicrosoftGame.config from a downloaded PC Game Pass title
    // (Balatro, StoreId 9PK087LNGJC5), trimmed to the relevant elements.
    const BALATRO_MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Game configVersion="1">
  <Identity Name="PlayStack.Balatro" Publisher="CN=8463DB6A-2934-499D-BE26-74ACA510B66F" Version="1.0.5.0" />
  <ExecutableList>
    <Executable Name="love.exe" TargetDeviceFamily="PC" Id="Balatro" />
  </ExecutableList>
  <StoreId>9PK087LNGJC5</StoreId>
</Game>"#;

    #[test]
    fn picks_the_pc_executable() {
        assert_eq!(
            parse_pc_executable(BALATRO_MANIFEST),
            Some("love.exe".to_string())
        );
    }

    #[test]
    fn skips_non_pc_and_dev_only_executables() {
        // Mirrors the reported real-world shape: a package can list several
        // executables for different device families (and dev-only tooling),
        // only one of which is the real thing to launch on PC.
        let xml = r#"<Game configVersion="1">
  <ExecutableList>
    <Executable Name="Game.Scarlett.exe" TargetDeviceFamily="Scarlett" Id="Game" />
    <Executable Name="Game.DevTools.exe" TargetDeviceFamily="PC" Id="Game" IsDevOnly="true" />
    <Executable Name="Game.exe" TargetDeviceFamily="PC" Id="Game" />
    <Executable Name="Game.XboxOne.exe" TargetDeviceFamily="XboxOne" Id="Game" />
  </ExecutableList>
</Game>"#;

        assert_eq!(parse_pc_executable(xml), Some("Game.exe".to_string()));
    }

    #[test]
    fn none_when_no_pc_executable_listed() {
        let xml = r#"<Game configVersion="1">
  <ExecutableList>
    <Executable Name="Game.XboxOne.exe" TargetDeviceFamily="XboxOne" Id="Game" />
  </ExecutableList>
</Game>"#;

        assert_eq!(parse_pc_executable(xml), None);
    }

    #[test]
    fn none_on_malformed_manifest() {
        assert_eq!(parse_pc_executable("not xml"), None);
    }
}
