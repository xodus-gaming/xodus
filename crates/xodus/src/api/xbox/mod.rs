use std::collections::HashSet;

use crate::auth::do_sisu;
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;
use crate::models::xbox::{
    Account, Atom, Atoms, Blob, BlobCreationRequest, BlobCreationResponse, BlobSubmitRequest,
    Blobs, Container, ContainerResponse, Containers, ContextDescription, Data, PagingInfo, Title,
    XbConnectedStorageSpace, XstsResponse,
};
use crate::tokens::TokenManager;

pub mod auth;
pub mod title;
pub use auth::{authenticate_xbox_user, get_xsts_auth_header, request_xsts_token};
use base64::Engine;
use bytes::Bytes;
use kryptering::random_bytes;
use reqwest::{Client, StatusCode};

pub async fn run(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
) -> XstsResponse {
    let user_token = crate::api::live::exchange_user_token(
        client,
        legacy,
        "USERNAME".to_string(),
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "user.auth.xboxlive.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .expect("Failed to get ms user token");

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            eprintln!("Failed to get exchange MS token");
            panic!("TODO");
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => unreachable!("Only responses are handled"),
    };
    let Token::Compact(user_token) = user_token else {
        eprintln!("Unsupported token");
        panic!("TODO");
    };
    let resp = authenticate_xbox_user(client, user_token)
        .await
        .expect("Failed to authenticate Xbox user");

    request_xsts_token(client, resp.token, relying_party)
        .await
        .expect("Failed to authenticate Xbox user")
}

pub async fn lock_container(
    client: &Client,
    token: &str,
    xuid: &str,
    scid: &str,
    pfn: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let r = client
        .put(
            format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/lock?friendlyName=linux"),
        )
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("x-xbl-pfn", pfn)
        .header("x-xbl-lock-ver", "1")
        .header("x-xbl-lock-ext", "301")
        .send()
        .await?
        .error_for_status()?;
    let t = r.text().await?;

    Ok(t)
}

pub async fn unlock_container(
    client: &Client,
    token: &str,
    xuid: &str,
    scid: &str,
    pfn: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let r = client
        .delete(
            format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/lock"),
        )
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("x-xbl-pfn", pfn)
        .header("x-xbl-lock-ver", "1")
        .header("x-xbl-lock-ext", "300")
        .send()
        .await?
        .error_for_status()?;

    let t = r.text().await?;

    Ok(t)
}

pub async fn fetch_containers(
    client: &Client,
    token: &str,
    xuid: &str,
    scid: &str,
    pfn: &str,
    continuation_token: Option<&str>,
) -> Result<ContainerResponse, Box<dyn std::error::Error>> {
    let r = client
        .get(format!(
            "https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}{}",
            continuation_token.map_or("".to_owned(), |c| format!("?continuationToken={c}"))
        ))
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("x-xbl-pfn", pfn)
        .send()
        .await?;

    if r.status() == StatusCode::NOT_FOUND {
        return Ok(ContainerResponse {
            blobs: vec![],
            paging_info: PagingInfo {
                continuation_token: None,
                total_items: 0,
            },
        });
    }

    let t = r.error_for_status()?.json::<ContainerResponse>().await?;

    Ok(t)
}

pub async fn fetch_all_containers(
    client: &Client,
    token: &str,
    xuid: &str,
    scid: &str,
    pfn: &str,
) -> Result<ContainerResponse, Box<dyn std::error::Error>> {
    let mut result = fetch_containers(client, token, xuid, scid, pfn, None).await?;

    while let Some(pi) = result.paging_info.continuation_token {
        let mut nr = fetch_containers(client, token, xuid, scid, pfn, Some(&pi)).await?;
        result.blobs.append(&mut nr.blobs);
        result.paging_info = nr.paging_info;
    }

    return Ok(result);
}

pub async fn create_container(
    client: &Client,
    token: &str,
    xuid: &str,
    scid: &str,
    pfn: &str,
    container_name: &str,
    client_file_time: Option<&str>,
    display_name: Option<&str>,
    bd: Atoms,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut u = url::Url::parse(&format!(
        "https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/savedgames/{container_name}"
    ))?;
    let mut q = u.query_pairs_mut();
    client_file_time.map(|t| q.append_pair("clientFileTime", t));
    display_name.map(|d| q.append_pair("displayName", d));
    let u = q.finish().as_str();
    let r = client
        .put(
            u,
        )
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("x-xbl-pfn", pfn)
        .header("content-type", "application/json")
        .header("x-xbl-lock-ext", "300")
        .json(&bd)
        .send()
        .await?
        /*.error_for_status()? */;

    let s = r.status();

    let t = r.text().await.unwrap();
    if !s.is_success() {
        panic!("{t}");
    }

    Ok(())
}

pub async fn fetch_container(
    client: &Client,
    token: &str,
    xuid: &str,
    scid: &str,
    container_name: &str,
    pfn: &str,
) -> Result<Atoms, Box<dyn std::error::Error>> {
    let r = client
        .get(
            format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/savedgames/{container_name}"),
        )
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("x-xbl-pfn", pfn)
        .send()
        .await?
        .error_for_status()?;

    let t = r.json::<Atoms>().await?;

    Ok(t)
}

pub async fn delete_container(
    client: &Client,
    token: &str,
    xuid: &str,
    scid: &str,
    container_name: &str,
    pfn: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client
        .delete(
            format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/savedgames/{container_name}"),
        )
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("x-xbl-pfn", pfn)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

pub async fn fetch_atom(
    client: &Client,
    token: &str,
    xuid: &str,
    scid: &str,
    atom: &str,
    pfn: &str,
) -> Result<bytes::Bytes, Box<dyn std::error::Error>> {
    let r = client
        .get(
            format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/{atom},binary"),
        )
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("x-xbl-pfn", pfn)
        .send()
        .await?
        .error_for_status()?;

    let t = r.bytes().await?;

    Ok(t)
}

pub async fn create_atom(
    client: &Client,
    token: &str,
    xuid: &str,
    scid: &str,
    atom: &str,
    pfn: &str,
    data: Bytes,
) -> Result<(), Box<dyn std::error::Error>> {
    let r = client
        .post(
            format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/atoms/{atom}"),
        )
        .json(&BlobCreationRequest {
            size: data.len() as i64,
        })
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("x-xbl-pfn", pfn)
        .header("x-xbl-lock-ext", "300")
        .send()
        .await?
        .error_for_status()?;

    let upload = r.json::<BlobCreationResponse>().await?;

    let blk_id = base64::engine::general_purpose::STANDARD_NO_PAD.encode(random_bytes(12).unwrap());

    let mut u = url::Url::parse(&upload.blob_uri)?;
    let u = u
        .query_pairs_mut()
        .append_pair("comp", "block")
        .append_pair("blockid", &blk_id)
        .finish()
        .as_str();

    let l = data.len() as i64;
    client
        .put(u)
        .header("content-length", l)
        .header("x-ms-blob-type", "BlockBlob")
        .body(data)
        .send()
        .await?
        .error_for_status()?;

    let r = client
        .post(
            format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/atoms/{atom}?commit=true"),
        )
        .json(&BlobSubmitRequest {
            block_ids: vec![blk_id],
            size: l,
        })
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("x-xbl-pfn", pfn)
        .header("x-xbl-lock-ext", "300")
        .send()
        .await?
        /*.error_for_status()? */;

    let s = r.status();

    let t = r.text().await.unwrap();
    if !s.is_success() {
        panic!("{s} msg {t}");
    }

    Ok(())
}

pub async fn download_connected_storage_xml(
    client: &Client,
    tokens: &TokenManager,
    client_id: &str,
    title_id: i64,
    pfn: &str,
    scid: Option<&str>,
) -> Result<XbConnectedStorageSpace, Box<dyn std::error::Error>> {
    let scid = scid.map_or_else(
        || uuid::Uuid::from_u64_pair(0, title_id as u64).to_string(),
        |v| v.to_owned(),
    );

    let (mut a, resp, dt) = do_sisu(client, tokens, client_id, title_id)
        .await
        .expect("ok");

    let xuid = &resp
        .authorization_token
        .display_claims
        .as_ref()
        .unwrap()
        .xui[0]["xid"];

    let ut = a
        .get_xsts_token(
            Some(&dt),
            None,
            Some(&resp.user_token),
            "http://xboxlive.com",
        )
        .await?;

    let mut out_containers = Vec::<Container>::new();

    let containers =
        fetch_all_containers(client, &ut.authorization_header_value(), xuid, &scid, pfn).await?;
    for e in &containers.blobs {
        let Some(cn) = e.file_name.strip_suffix(",savedgame") else {
            continue;
        };
        let mut blobs = Vec::<Blob>::new();
        let ci = fetch_container(
            client,
            &ut.authorization_header_value(),
            xuid,
            &scid,
            cn,
            pfn,
        )
        .await?;
        for a in &ci.atoms {
            let ac = fetch_atom(
                client,
                &ut.authorization_header_value(),
                xuid,
                &scid,
                &a.atom,
                pfn,
            )
            .await?;
            blobs.push(Blob {
                name: a.name.to_owned(),
                data: base64::engine::general_purpose::STANDARD.encode(ac),
            });
        }
        out_containers.push(Container {
            name: cn.to_owned(),
            client_file_time: e.client_file_time.clone(),
            etag: Some(e.etag.clone()),
            display_name: e.display_name.clone(),
            blobs: Blobs { blob: blobs },
        });
    }

    Ok(XbConnectedStorageSpace {
        context_description: ContextDescription {
            account: Account {
                msa: "me".to_owned(),
            },
            title: Title { scid },
        },
        data: Data {
            containers: Containers {
                container: out_containers,
            },
        },
    })
}

pub async fn upload_connected_storage_xml(
    client: &Client,
    tokens: &TokenManager,
    client_id: &str,
    title_id: i64,
    pfn: &str,
    scid: Option<&str>,
    storage: XbConnectedStorageSpace,
    keep_existing: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let scid = scid.map_or_else(
        || uuid::Uuid::from_u64_pair(0, title_id as u64).to_string(),
        |v| v.to_owned(),
    );

    let (mut a, resp, dt) = do_sisu(client, tokens, client_id, title_id)
        .await
        .expect("ok");

    let xuid = &resp
        .authorization_token
        .display_claims
        .as_ref()
        .unwrap()
        .xui[0]["xid"];

    let ut = a
        .get_xsts_token(
            Some(&dt),
            None,
            Some(&resp.user_token),
            "http://xboxlive.com",
        )
        .await?;

    let _ = lock_container(client, &ut.authorization_header_value(), xuid, &scid, pfn).await?;

    let containers =
        fetch_all_containers(client, &ut.authorization_header_value(), xuid, &scid, pfn).await?;

    let mut to_keep = HashSet::new();

    for c in &storage.data.containers.container {
        if let Some((i, b)) = containers.blobs.iter().enumerate().find(|(_, b)| {
            b.file_name
                .strip_suffix(",savedgame")
                .map_or(false, |v| v == c.name)
        }) {
            if c.etag.as_deref().map_or(false, |t| t == b.etag) {
                // Already up to date
                to_keep.insert(i);
                continue;
            }
            to_keep.insert(i);
        }

        let mut atoms = Vec::new();

        for atom in &c.blobs.blob {
            let b = base64::engine::general_purpose::STANDARD.decode(&atom.data)?;

            let a = Atom {
                atom: uuid::Uuid::new_v4().to_string().to_uppercase(),
                name: atom.name.clone(),
                size: b.len() as i64,
            };

            create_atom(
                client,
                &ut.authorization_header_value(),
                xuid,
                &scid,
                &a.atom,
                pfn,
                b.into(),
            )
            .await?;

            atoms.push(a);
        }
        create_container(
            client,
            &ut.authorization_header_value(),
            xuid,
            &scid,
            pfn,
            &c.name,
            c.client_file_time.as_deref(),
            c.display_name.as_deref(),
            Atoms { atoms: atoms },
        )
        .await?;
    }

    if !keep_existing {
        for (i, e) in containers.blobs.iter().enumerate() {
            if !to_keep.contains(&i) {
                if let Some(container_name) = e.file_name.strip_suffix(",savedgame") {
                    delete_container(
                        client,
                        &ut.authorization_header_value(),
                        xuid,
                        &scid,
                        container_name,
                        pfn,
                    )
                    .await?;
                }
            }
        }
    }

    unlock_container(client, &ut.authorization_header_value(), xuid, &scid, pfn).await?;
    Ok(())
}
