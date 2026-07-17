use base64::prelude::*;
use xodus::licensing::splicense::SPLicense;
pub fn run(block: String) {
    let license = SPLicense::parse_base64(block).expect("Failed to parse SPLicenseBlock");
    let clep_sign_state = license.clep_sign_state.unwrap();
    let key = clep_sign_state.get_rsa_key();

    println!("RSA key is {:?}", BASE64_STANDARD.encode(key))
}
