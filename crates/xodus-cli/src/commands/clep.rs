use base64::prelude::*;
use xodus::clep::challenge::{clep_deobfuscate, get_license_challange};

pub fn generate(smbios: Option<String>, disk_serial: Option<String>) {
    let mut smbios_buf = [0u8; 256];
    let mut disk_serial_buf = [0u8; 64];

    if let Some(smbios) = smbios
        && let Err(err) = fill(&mut smbios_buf, &smbios, "smbios")
    {
        eprintln!("{err}");
        return;
    }
    if let Some(disk_serial) = disk_serial
        && let Err(err) = fill(&mut disk_serial_buf, &disk_serial, "disk-serial")
    {
        eprintln!("{err}");
        return;
    }

    let (v2, v4) = get_license_challange(smbios_buf, disk_serial_buf);
    println!("v2: {}", BASE64_STANDARD.encode(v2));
    println!("v4: {}", BASE64_STANDARD.encode(v4));
}

pub fn decrypt(data: String) {
    let decoded = match BASE64_STANDARD.decode(&data) {
        Ok(decoded) => decoded,
        Err(err) => {
            eprintln!("invalid base64 input: {err}");
            return;
        }
    };
    let Ok(mut buffer) = <[u8; 2048]>::try_from(decoded) else {
        eprintln!("expected 2048 bytes of challenge data, got a different length");
        return;
    };

    clep_deobfuscate(&mut buffer);

    let version = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    let smbios = &buffer[4..260];
    let disk_serial = &buffer[260..324];

    println!("version: {version}");
    println!("smbios: {}", BASE64_STANDARD.encode(smbios));
    println!("disk_serial: {}", BASE64_STANDARD.encode(disk_serial));
    println!("plaintext: {}", BASE64_STANDARD.encode(buffer));
}

fn fill(buf: &mut [u8], base64_data: &str, name: &str) -> Result<(), String> {
    let decoded = BASE64_STANDARD
        .decode(base64_data)
        .map_err(|err| format!("invalid base64 for {name}: {err}"))?;
    if decoded.len() > buf.len() {
        return Err(format!(
            "{name} is too long: got {} bytes, max is {}",
            decoded.len(),
            buf.len()
        ));
    }
    buf[..decoded.len()].copy_from_slice(&decoded);
    Ok(())
}
