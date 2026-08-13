// Hardware probing utilities

use std::io;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

use base64::prelude::*;
#[cfg(any(target_os = "macos", target_os = "ios", target_family = "windows"))]
use smbioslib::raw_smbios_from_device;
#[cfg(not(target_os = "linux"))]
use smbioslib::{SMBiosSystemInformation, SystemUuidData, table_load_from_device};

use crate::clep;
use crate::models::devicecredential::Component;

pub fn probe_provision_components() -> Vec<Component> {
    let mut components = Vec::with_capacity(16);
    let drive_serial = BASE64_STANDARD.decode("AA==").unwrap();
    let mut smbios_buf = [0; 256];
    let mut drive_buf = [0; 64];

    let smbios = load_raw_smbios().ok();
    let parsed_smbios = load_smbios_fields(smbios.as_deref()).ok();

    drive_buf
        .iter_mut()
        .zip(drive_serial.iter())
        .for_each(|(place, data)| *place = *data);
    if let Some(smbios) = smbios.as_ref() {
        smbios_buf
            .iter_mut()
            .zip(smbios.iter())
            .for_each(|(place, data)| *place = *data);
    }
    let (clepv2, clepv4) = clep::challenge::get_license_challange(smbios_buf, drive_buf);

    components.push(Component::new(4113, "AA==".to_string()));
    components.push(Component::error(4101));
    components.push(Component::new(8196, BASE64_STANDARD.encode(clepv2)));
    components.push(Component::new(8197, BASE64_STANDARD.encode(clepv4)));

    if let Some((version, serial, uuid)) = parsed_smbios {
        components.push(Component::new(4100, BASE64_STANDARD.encode(version)));
        components.push(Component::new(4101, BASE64_STANDARD.encode(serial)));
        components.push(Component::new(4102, BASE64_STANDARD.encode(uuid)));
    } else {
        components.push(Component::error(4100));
        components.push(Component::error(4101));
        components.push(Component::error(4102));
    }

    components.push(Component::new(4145, "AQAAAA==".to_string()));
    components.push(Component::error(4160));
    components.push(Component::error(4161));

    // Common values sent with the request
    // "4128"
    // "4130"
    // "4112"
    // "4113"
    // "4098"
    // "4099"
    // "4100"
    // "4101"
    // "4102"
    // "4097"
    // "8195"
    // "8196"
    // "8197"
    // "4144"
    // "4145"
    // "4160"
    // "4161"

    components
}

#[cfg(target_os = "linux")]
fn load_smbios_fields(raw: Option<&[u8]>) -> io::Result<(Vec<u8>, Vec<u8>, [u8; 16])> {
    let smbios =
        raw.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing raw SMBIOS data"))?;
    Ok(parse_smbios(smbios))
}

#[cfg(not(target_os = "linux"))]
fn load_smbios_fields(_raw: Option<&[u8]>) -> io::Result<(Vec<u8>, Vec<u8>, [u8; 16])> {
    let data = table_load_from_device()?;
    let system_info = data
        .first::<SMBiosSystemInformation>()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing SMBIOS Type 1"))?;

    let version = system_info
        .version()
        .to_utf8_lossy()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing SMBIOS version"))?
        .into_bytes();
    let serial = system_info
        .serial_number()
        .to_utf8_lossy()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing SMBIOS serial"))?
        .into_bytes();
    let uuid = match system_info.uuid() {
        Some(SystemUuidData::Uuid(uuid)) => uuid.raw,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing SMBIOS UUID",
            ));
        }
    };

    Ok((version, serial, uuid))
}

#[cfg(target_os = "linux")]
fn parse_smbios(smbios: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; 16]) {
    let length = smbios[1];

    let version = smbios[6];
    let serial = smbios[7];
    let uuid: [u8; 16] = smbios[8..24].try_into().unwrap();

    let stringsbuf = &smbios[length as usize..];
    let mut strings: Vec<&[u8]> = Vec::new();
    strings.push(&[]);
    let mut cursor = 0;
    while cursor < stringsbuf.len() {
        let end = stringsbuf[cursor..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(stringsbuf.len() - cursor)
            + cursor;
        let slice = &stringsbuf[cursor..end];
        strings.push(slice);
        cursor = end + 1;
        if cursor >= stringsbuf.len() || stringsbuf[cursor] == 0 {
            break;
        }
    }

    (
        strings[version as usize].to_vec(),
        strings[serial as usize].to_vec(),
        uuid,
    )
}

#[cfg(any(target_os = "macos", target_os = "ios", target_family = "windows"))]
fn load_raw_smbios() -> io::Result<Vec<u8>> {
    raw_smbios_from_device()
}

// Common polkit authentication agent binaries across desktop environments.
// pkexec needs one of these (or an equivalent) registered on the session bus
// to ever show a prompt; without one it blocks in `pkexec` forever with no
// error (confirmed live - `pstree` on the stuck tree shows `pkexec` sitting
// idle on `do_wait`). This list isn't exhaustive (a custom/rare agent won't
// match), but it covers the desktop environments this is actually likely to
// run under; an unmatched-but-present agent just means the fallback below
// (attempt pkexec anyway) is safe, since a real agent showing a prompt means
// pkexec correctly returns once the user answers it, one way or another.
const KNOWN_POLKIT_AGENTS: &[&str] = &[
    "polkit-gnome-authentication-agent-1",
    "polkit-kde-authentication-agent-1",
    "lxqt-policykit-agent",
    "lxpolkit",
    "mate-polkit",
    "xfce-polkit",
    "ukui-polkit",
];

fn polkit_agent_running() -> bool {
    // -f (match against the full command line) rather than -x (match against
    // `comm`, which the kernel truncates to 15 characters): several agent
    // binary names exceed that, e.g. polkit-kde-authentication-agent-1 (34
    // chars, truncated to "polkit-kde-auth" in /proc/<pid>/comm), so -x would
    // silently never match them and always report no agent present.
    //
    // The pattern anchors the name to a path component (leading `/`) and
    // requires it be followed by whitespace or end-of-string, so it only
    // matches the agent binary actually being invoked, not an unrelated
    // process whose arguments merely happen to contain the name as a
    // substring - a false positive here would reintroduce the original
    // infinite-hang bug by making a real pkexec call with no agent present.
    KNOWN_POLKIT_AGENTS.iter().any(|name| {
        Command::new("pgrep")
            .args(["-f", &format!("/{name}([[:space:]]|$)")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

#[cfg(target_os = "linux")]
fn load_raw_smbios() -> io::Result<Vec<u8>> {
    // If no authentication agent is registered, pkexec cannot ever prompt for
    // a password and will hang forever waiting on one that will never appear
    // (see KNOWN_POLKIT_AGENTS doc comment) - fail immediately instead of
    // guessing at a timeout that's either too short for a real password
    // prompt or still an arbitrarily long hang for the no-agent case.
    if !polkit_agent_running() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no polkit authentication agent detected for this session; unable to probe SMBIOS data",
        ));
    }

    // An agent is present, so this is a real, human-driven authentication
    // prompt - pkexec will return on its own once the user answers it
    // (success, wrong password exhausting retries, or the dialog is
    // dismissed/canceled), so there's no good arbitrary timeout to apply
    // here without cutting off a legitimately slow person mid-prompt.
    let output = Command::new("pkexec")
        .args(["cat", "/sys/firmware/dmi/entries/1-0/raw"])
        .stdout(Stdio::piped())
        .output()?;

    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unable to probe SMBIOS data",
        ))
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_family = "windows"
)))]
fn load_raw_smbios() -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "raw SMBIOS loading is unsupported on this platform",
    ))
}
