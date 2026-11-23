use std::process::ExitCode;

#[cfg(feature = "firefox")]
use serde_core::de::IntoDeserializer;
#[cfg(feature = "firefox")]
use serde_json::Value;
#[cfg(any(feature = "firefox", feature = "chromeium"))]
use xodus::models::live::DAProperty;
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::{secrets, soap};
use xodus::tokens::TokenManager;

const CLIENT_ID: &str = "0000000040159362";
const USER_AUTH_SCOPE: &str = "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0&clientid=0000000040159362&ssoappgroup=none";

#[cfg(feature = "firefox")]
async fn resolve_browser(start_url: &str, target_url: &str) -> DAProperty {
    use ff_rdp_core::{ActorId, WebConsoleActor};
    use std::time::Duration;
    let con: ff_rdp_core::RdpConnection =
        ff_rdp_core::connection::RdpConnection::connect("localhost", 6000, Duration::from_secs(30))
            .unwrap();
    let mut transport = con.into_transport();
    let tabs = ff_rdp_core::RootActor::list_tabs(&mut transport).unwrap();
    let mut tab = tabs.first().unwrap();
    let mut a = ff_rdp_core::TabActor::get_target(&mut transport, &tab.actor).unwrap();
    let mut wait_for_change = if a.url.is_none() || a.url.as_ref().unwrap() != start_url {
        ff_rdp_core::WindowGlobalTarget::navigate_to(&mut transport, &a.actor, start_url).unwrap();
        true
    } else {
        false
    };

    loop {
        let url = match ff_rdp_core::WindowGlobalTarget::current_url(&mut transport, &a.actor) {
            Err(e) => {
                println!("error {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
                let con: ff_rdp_core::RdpConnection =
                    ff_rdp_core::connection::RdpConnection::connect(
                        "localhost",
                        6000,
                        Duration::from_secs(30),
                    )
                    .unwrap();
                transport = con.into_transport();
                let tabs = ff_rdp_core::RootActor::list_tabs(&mut transport).unwrap();
                tab = tabs.first().unwrap();
                a = ff_rdp_core::TabActor::get_target(&mut transport, &tab.actor).unwrap();
                continue;
            }
            Ok(Some(url)) => url,
            Ok(None) => {
                println!("error none");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        if wait_for_change && a.url.as_ref().is_some() && url == *a.url.as_ref().unwrap() {
            println!("{url}");
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }
        wait_for_change = false;
        if url.starts_with(target_url) {
            break;
        }
    }

    println!("read data");
    loop {
        let response = match ff_rdp_core::WebConsoleActor::evaluate_js_async(
            &mut transport,
            &a.console_actor,
            "JSON.stringify(ServerData)",
        ) {
            Ok(r) => r,
            Err(e) => {
                println!("{}", e);
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        let s = match response.result {
            ff_rdp_core::Grip::Value(value) => value.to_string(),
            ff_rdp_core::Grip::LongString {
                actor,
                length,
                initial,
            } => {
                _ = initial;
                ff_rdp_core::LongStringActor::full_string(&mut transport, actor.as_ref(), length)
                    .unwrap_or_default()
            }
            _ => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        let val = match serde_json::from_str(&s) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", s);
                println!("{}", e);
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        return val;
    }
}

#[cfg(feature = "chromeium")]
async fn resolve_browser(start_url: &str, target_url: &str) -> DAProperty {
    use chromiumoxide::Browser;
    use futures_util::StreamExt;
    use std::time::Duration;
    let (browser, mut handler) = Browser::connect("http://localhost:6000").await.unwrap();
    tokio::task::spawn(async move {
        while let Some(h) = handler.next().await {
            if h.is_err() {
                break;
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let pages = browser.pages().await.unwrap();
    if let Some(page) = pages.first() {
        println!("page");
        page.goto(start_url).await.unwrap();
        loop {
            page.wait_for_navigation().await.unwrap();
            if let Ok(Some(url)) = page.url().await
                && url.starts_with(target_url)
            {
                let res = page.evaluate("ServerData").await.unwrap();
                let v = res.value().unwrap();
                return serde_json::from_value(v.clone()).unwrap();
            }
        }
    }
    unreachable!()
}

#[cfg(any(feature = "chromeium", feature = "firefox"))]
pub async fn run(client: &reqwest::Client, tokens: &TokenManager) -> ExitCode {
    let token = tokens.get_device_sts_token().unwrap();
    let secrets::Token::Legacy(token) = token else {
        eprintln!("Invalid STS token");
        return ExitCode::FAILURE;
    };
    let device_token = token.clone();
    let client_id = CLIENT_ID.to_string().clone();
    let username = "USERNAME".to_owned();
    let mut user_token = xodus::models::secrets::LegacyToken {
        key_name: None,
        token: "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"devicesoftware\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\"></EncryptionMethod><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyName>http://Passport.NET/STS</ds:KeyName></ds:KeyInfo><CipherData><CipherValue>challenge</CipherValue></CipherData></EncryptedData>".to_owned(),
        binary_secret: None,
        tpm_key: None,
        lifetime: soap::Timestamp {
            id: None,
            created: "".to_owned(),
            expires: "".to_owned(),
        },
    };

    let mut scopes = vec![(
        USER_AUTH_SCOPE.to_string(),
        Some(soap::PolicyReference::token_broker()),
    )];

    scopes.push(("http://Passport.NET/tb".to_string(), None));

    let mut user_data = None;

    loop {
        let outcome = xodus::api::live::exchange_user_token(
            &client,
            user_token.clone(),
            username.clone(),
            device_token.clone(),
            None,
            None,
            client_id.clone(),
            &scopes,
        )
        .await
        .unwrap();

        let final_token: Token = match outcome {
            ExchangeUserTokenOutcome::Fault(Some(pp)) => {
                println!("login url: {}", pp.inline_auth_url.as_deref().unwrap());
                println!(
                    "login end url: {}",
                    pp.inline_end_auth_url.as_deref().unwrap()
                );
                let rdata = resolve_browser(
                    pp.inline_auth_url.as_deref().unwrap(),
                    "https://login.live.com/ppsecure/post.srf",
                )
                .await;
                user_token.token = rdata.da_token.clone();
                user_data = Some(rdata);
                continue;
            }
            ExchangeUserTokenOutcome::Fault(_) => {
                return ExitCode::FAILURE;
            }
            ExchangeUserTokenOutcome::Issued(
                soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
            ) => {
                let token = collection.security_tokens.remove(0);
                if let Some(pp) = &token.pp {
                    if pp.inline_auth_url.as_deref().is_some() {
                        println!("login url: {}", pp.inline_auth_url.as_deref().unwrap());
                        println!(
                            "login end url: {}",
                            pp.inline_end_auth_url.as_deref().unwrap()
                        );
                        let rdata = resolve_browser(
                            pp.inline_auth_url.as_deref().unwrap(),
                            "https://login.live.com/ppsecure/post.srf",
                        )
                        .await;
                        user_token.token = rdata.da_token.clone();
                        user_data = Some(rdata);
                        continue;
                    }
                    println!("error {}", pp.error_status.as_ref().unwrap());
                    println!("rstatus {}", pp.req_status.as_ref().unwrap());
                    println!("payload {}", quick_xml::se::to_string(pp).unwrap());
                    println!("Failure");
                    return ExitCode::FAILURE;
                }
                for token in collection.security_tokens {
                    let address = token
                        .applies_to
                        .as_ref()
                        .unwrap()
                        .endpoint_reference
                        .address
                        .clone();
                    let token = token.into();
                    let address = if let secrets::Token::Legacy(legacy) = &token {
                        legacy.key_name.clone().unwrap_or(address)
                    } else {
                        address
                    };
                    tokens.save_user_token(address, token).unwrap();
                }
                token.into()
            }
            ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
                token,
            )) => (*token).into(),
            _ => unreachable!("Only responses are handled"),
        };

        match final_token {
            Token::Legacy(legacy_token) => println!("legacy {}", legacy_token.token),
            Token::Compact(c) => println!("compact {c}"),
        }
        user_data.map(|user_data| {
            tokens
                .save_user(&xodus::models::secrets::User {
                    puid: user_data.puid,
                    username: user_data.username,
                })
                .unwrap();
        });
        return ExitCode::SUCCESS;
    }
}
