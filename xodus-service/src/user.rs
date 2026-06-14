use std::collections::HashMap;

use xodus::models::secrets::{Token, TokenStore};

pub fn get_token(address: &str) -> Option<Token> {
    let entry = xodus::secrets::get_entry("user-tokens").unwrap();
    let passwd = entry.get_password().unwrap_or_default();

    let tokens = if !passwd.is_empty() {
        let tokens = serde_json::from_str::<TokenStore>(&passwd).unwrap();
        tokens.tokens
    } else {
        HashMap::new()
    };
    tokens.get(address).cloned()
}
