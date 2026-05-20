// Hardware probing utilities

use crate::{clep, models::devicecredential::Component};
use base64::prelude::*;
use std::process::{Command, ExitStatus, Stdio};

pub fn probe_provision_components() -> Vec<Component> {
    let mut components = Vec::with_capacity(16);
    let cmd = Command::new("pkexec")
        .args(["cat", "/sys/firmware/dmi/entries/1-0/raw"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to get hardware entries");
    let output = cmd.wait_with_output().expect("Failed to wait");
    if !output.status.success() {
        panic!("Unable to probe SMBIOS data");
    }
    let smbios = output.stdout;
    let (_manufacturer, version, serial, uuid) = parse_smbios(&smbios);
    let drive_serial = BASE64_STANDARD.decode("AA==").unwrap();
    let mut smbios_buf = [0; 256];
    let mut drive_buf = [0; 64];
    drive_buf
        .iter_mut()
        .zip(drive_serial.iter())
        .for_each(|(place, data)| *place = *data);
    smbios_buf
        .iter_mut()
        .zip(smbios.iter())
        .for_each(|(place, data)| *place = *data);
    let (clepv2, clepv4) = clep::challenge::get_license_challange(smbios_buf, drive_buf);

    components.push(Component::new(4113, "AA==".to_string()));
    components.push(Component::error(4101));
    components.push(Component::new(8196, BASE64_STANDARD.encode(clepv2)));
    components.push(Component::new(8197, BASE64_STANDARD.encode(clepv4)));
    components.push(Component::new(4100, BASE64_STANDARD.encode(version)));
    components.push(Component::new(4101, BASE64_STANDARD.encode(serial)));
    components.push(Component::new(4102, BASE64_STANDARD.encode(uuid)));
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

fn parse_smbios(smbios: &[u8]) -> (&[u8], &[u8], &[u8], [u8;16]){
    let ttype = smbios[0];
    let length = smbios[1];
    let handle = u16::from_le_bytes(smbios[2..4].try_into().unwrap());

    let manufacturer = smbios[4];
    let product = smbios[5];
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

    let manufacturer = strings[manufacturer as usize];
    let version= strings[version as usize];
    let serial = strings[serial as usize];

    (manufacturer, version, serial, uuid)
}
