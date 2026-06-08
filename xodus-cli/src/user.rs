use xodus::models::secrets::User;

pub fn save_user(user: User) {
    let entry = xodus::secrets::get_entry("user-DA").unwrap();
    let user_str = serde_json::to_string(&user).unwrap();
    entry.set_secret(user_str.as_bytes()).unwrap();
}

pub fn get_user() -> Result<xodus::models::secrets::User, Box<dyn std::error::Error>> {
    let device_entry = xodus::secrets::get_entry("user-DA")?;
    let secret = device_entry.get_secret()?;
    let t = serde_json::from_slice::<xodus::models::secrets::User>(&secret.as_slice())?;
    Ok(t)
}
