use std::path::{Path, PathBuf};
use std::time::Duration;
use xodus::api::live::RSTError;
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::{LegacyToken, Token};
use xodus::models::soap;
use xodus::models::xgameruntime::xuser::{MSATokenErrorResponse, MSATokenRequest, MSATokenResponse};
use xodus::tokens::store::TokenStoreError;

use crate::simple_context::SimpleContext;

const E_FAIL: &str = "0x80004005";
const SIGN_IN_REQUIRED: &str = "0x8004100c";
/// What XUserAddResult returns when the user cancels the sign-in UI (GDK docs).
const E_ABORT: &str = "0x80004004";
/// `xodus-cli login` exit status when the window was closed without a token.
const LOGIN_CANCELLED_EXIT: i32 = 2;

#[derive(Debug)]
pub enum ServiceError {
    SignInRequired,
    Cancelled,
    Code(String),
    Other(String),
}

impl ServiceError {
    pub fn code(&self) -> String {
        match self {
            ServiceError::SignInRequired => SIGN_IN_REQUIRED.to_string(),
            ServiceError::Cancelled => E_ABORT.to_string(),
            ServiceError::Code(c) => c.clone(),
            ServiceError::Other(_) => E_FAIL.to_string(),
        }
    }
}

impl From<RSTError> for ServiceError {
    fn from(e: RSTError) -> Self {
        match e {
            RSTError::Fault(f) if f.is_sign_in_required() => ServiceError::SignInRequired,
            RSTError::Fault(f) => ServiceError::Code(f.error_code()),
            other => ServiceError::Other(other.to_string()),
        }
    }
}

/// Serialized failure reply; never empty.
pub fn error_body(e: &ServiceError) -> Vec<u8> {
    if let ServiceError::Other(msg) = e {
        tracing::warn!("MSA token request failed: {msg}");
    }
    quick_xml::se::to_string(&MSATokenErrorResponse { error: e.code() })
        .unwrap_or_else(|_| format!("<MSATokenResponse><Error>{E_FAIL}</Error></MSATokenResponse>"))
        .into_bytes()
}

/// Stored-token lookup failure: missing => sign-in needed; anything else is a real failure.
pub fn map_token_error(e: TokenStoreError) -> ServiceError {
    match e {
        TokenStoreError::NotFound => ServiceError::SignInRequired,
        other => ServiceError::Other(other.to_string()),
    }
}

fn require_legacy(t: Token) -> Result<LegacyToken, ServiceError> {
    match t {
        Token::Legacy(l) => Ok(l),
        Token::Compact(_) => Err(ServiceError::SignInRequired),
    }
}

pub fn take_security_token<T>(tokens: Vec<T>) -> Result<T, ServiceError> {
    tokens
        .into_iter()
        .next()
        .ok_or_else(|| ServiceError::Other("no security token in response".into()))
}

pub fn success_body(
    user_token: String,
    expiry: i64,
    device: Option<(String, i64)>,
) -> Result<Vec<u8>, ServiceError> {
    let (device_rps, device_expiry) = device.unwrap_or_default();
    let payload = MSATokenResponse {
        token: user_token,
        expiry,
        device_rps,
        device_expiry,
    };
    quick_xml::se::to_string(&payload)
        .map(String::into_bytes)
        .map_err(|e| ServiceError::Other(e.to_string()))
}

fn rst_timeout(allow_ui: bool) -> Option<Duration> {
    allow_ui.then_some(Duration::from_secs(20))
}

/// A failed device exchange is non-fatal: the reply just carries no DeviceRps.
fn device_rps(r: Result<soap::RequestSecurityTokenResponse, RSTError>) -> Option<(String, i64)> {
    match r {
        Ok(t) => match (
            Token::from(t.clone()),
            chrono::DateTime::parse_from_rfc3339(&t.lifetime.expires),
        ) {
            (Token::Compact(rps), Ok(exp)) => Some((rps, exp.timestamp())),
            _ => None,
        },
        Err(e) => {
            tracing::warn!("Device token exchange failed: {e}");
            None
        }
    }
}

pub async fn exchange_msa_token(
    req: &MSATokenRequest,
    ctx: &SimpleContext,
) -> Result<Vec<u8>, ServiceError> {
    let token = require_legacy(ctx.tokens().get_user_sts_token().map_err(map_token_error)?)?;
    let scope = if req.msa_full_trust {
        "service::user.auth.xboxlive.com::MBI_SSL"
    } else {
        "xboxlive.signin"
    };
    let device_token = ctx
        .device_token
        .as_ref()
        .ok_or_else(|| ServiceError::Other("no device token".into()))?;
    let timeout = rst_timeout(req.allow_ui);

    let device = device_rps(
        xodus::api::live::exchange_device_token(
            &ctx.client,
            device_token.clone(),
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL".to_owned(),
            Some(soap::PolicyReference::token_broker()),
            timeout,
        )
        .await,
    );

    let outcome = xodus::api::live::exchange_user_token(
        &ctx.client,
        token,
        "USERNAME".to_string(),
        device_token.clone(),
        None,
        Some("Silent".to_string()),
        req.client_id.clone(),
        &[
            (
                format!("scope={scope}&api-version=2.0&clientid={}", req.client_id),
                Some(soap::PolicyReference::token_broker()),
            ),
            ("http://Passport.NET/tb".to_string(), None),
        ],
        timeout,
    )
    .await?;

    let ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponseCollection(
        mut collection,
    )) = outcome
    else {
        return Err(ServiceError::Other(format!(
            "User token exchange was not issued: {outcome:?}"
        )));
    };
    if collection.security_tokens.len() > 1
        && let Some(sts) = collection.security_tokens.pop()
    {
        let address = sts.applies_to.endpoint_reference.address.clone();
        let sts: Token = sts.into();
        let address = match &sts {
            Token::Legacy(l) => l.key_name.clone().unwrap_or(address),
            _ => address,
        };
        if let Err(err) = ctx.tokens().save_user_token(address, sts) {
            tracing::warn!("Failed to persist refreshed STS token: {err}");
        }
    }
    let token = take_security_token(collection.security_tokens)?;
    let expiry = chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)
        .map_err(|e| ServiceError::Other(e.to_string()))?;
    let Token::Compact(user_token) = Token::from(token) else {
        return Err(ServiceError::Other("user token was not compact".into()));
    };
    success_body(user_token, expiry.timestamp(), device)
}

const LOGIN_TIMEOUT: Duration = Duration::from_secs(600);
const LOGIN_TIMEOUT_MSG: &str =
    "xodus-cli login timed out after 600 s; close/complete the sign-in window and retry in the game";

/// `XODUS_CLI` (empty = unset), else `xodus-cli` next to the current executable.
pub fn resolve_cli_path() -> PathBuf {
    resolve_cli_path_from(std::env::var("XODUS_CLI").ok().as_deref())
}

pub fn resolve_cli_path_from(env: Option<&str>) -> PathBuf {
    match env {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => {
            let mut p = std::env::current_exe().unwrap_or_default();
            p.set_file_name("xodus-cli");
            p
        }
    }
}

pub async fn run_login() -> Result<(), ServiceError> {
    run_login_with(&resolve_cli_path(), LOGIN_TIMEOUT).await
}

/// Runs `<path> login`. Exit status 2 (window closed) is a cancel; any other exit lets the
/// caller's retry decide success.
pub async fn run_login_with(path: &Path, timeout: Duration) -> Result<(), ServiceError> {
    let mut child = tokio::process::Command::new(path)
        .arg("login")
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            let msg = format!(
                "cannot start xodus-cli at {}: {e}; set XODUS_CLI to the xodus-cli binary or install it next to xodus-service",
                path.display()
            );
            tracing::error!("{msg}");
            ServiceError::Other(msg)
        })?;
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) if status.code() == Some(LOGIN_CANCELLED_EXIT) => {
            tracing::warn!("sign-in window closed without signing in; replying {E_ABORT}");
            Err(ServiceError::Cancelled)
        }
        Ok(_) => Ok(()),
        Err(_) => {
            let _ = child.kill().await;
            tracing::error!("{LOGIN_TIMEOUT_MSG}");
            Err(ServiceError::Other(LOGIN_TIMEOUT_MSG.to_string()))
        }
    }
}

static LOGIN_COUNT: tokio::sync::Mutex<u64> = tokio::sync::Mutex::const_new(0);
const DEADLINE_NO_UI: Duration = Duration::from_secs(4);
/// The AllowUi=true deadline, not a budget: a sign-in completing after about 590 s may reply
/// 0x80004005 with the token already stored, and the next request succeeds (no remaining-budget
/// logic). xgameruntime waits 620 s (MSA_UI_REQUEST_TIMEOUT_MS).
const DEADLINE_UI: Duration = Duration::from_secs(610);

pub async fn handle_msa_token(req: &MSATokenRequest, ctx: &SimpleContext) -> Vec<u8> {
    handle_with(req, |r| exchange_msa_token(r, ctx), run_login, &LOGIN_COUNT).await
}

/// Always-reply flow: exchange, and on SignInRequired with AllowUi run a single-flight login
/// then re-run the exchange once. The whole request is bounded by a deadline.
pub async fn handle_with<'a, E, EF, L, LF>(
    req: &'a MSATokenRequest,
    exchange: E,
    login: L,
    login_count: &tokio::sync::Mutex<u64>,
) -> Vec<u8>
where
    E: Fn(&'a MSATokenRequest) -> EF,
    EF: std::future::Future<Output = Result<Vec<u8>, ServiceError>>,
    L: Fn() -> LF,
    LF: std::future::Future<Output = Result<(), ServiceError>>,
{
    let deadline = if req.allow_ui { DEADLINE_UI } else { DEADLINE_NO_UI };
    let flow = async {
        // A held mutex means a login is in progress (it already bumped the count), so the
        // count is certain to differ by the time we acquire it: None = "changed".
        let n = login_count.try_lock().ok().map(|g| *g);
        let mut r = exchange(req).await;
        if matches!(r, Err(ServiceError::SignInRequired)) && req.allow_ui {
            let mut count = login_count.lock().await;
            if n == Some(*count) {
                *count += 1;
                match login().await {
                    Err(e) => r = Err(e),
                    Ok(()) => r = exchange(req).await,
                }
            } else {
                r = exchange(req).await;
            }
            if matches!(r, Err(ServiceError::SignInRequired)) {
                tracing::warn!("sign-in still required after login; replying 0x8004100c");
            }
        }
        r
    };
    match tokio::time::timeout(deadline, flow).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            tracing::error!("MSA token exchange failed: {e:?}");
            error_body(&e)
        }
        Err(_) => error_body(&ServiceError::Other("exchange timed out".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xodus::api::live::SoapFault;

    fn body(e: ServiceError) -> String {
        String::from_utf8(error_body(&e)).unwrap()
    }

    #[test]
    fn error_body_sign_in_required() {
        assert_eq!(
            body(ServiceError::SignInRequired),
            "<MSATokenResponse><Error>0x8004100c</Error></MSATokenResponse>"
        );
    }

    #[test]
    fn error_body_fault_internal_code() {
        let f = SoapFault {
            internal_code: Some("0x80048831".into()),
            ..Default::default()
        };
        let e: ServiceError = RSTError::Fault(f).into();
        assert!(body(e).contains("<Error>0x80048831</Error>"));
    }

    #[test]
    fn error_body_sign_in_fault_maps() {
        let f = SoapFault {
            value: Some("0x800488e5".into()),
            ..Default::default()
        };
        assert!(matches!(RSTError::Fault(f).into(), ServiceError::SignInRequired));
    }

    #[test]
    fn error_body_other() {
        let b = body(ServiceError::Other("x".into()));
        assert!(b.contains("<Error>0x80004005</Error>"));
        assert!(!b.contains("<Token>"));
        assert!(!b.is_empty());
    }

    fn msg(e: ServiceError) -> String {
        match e {
            ServiceError::Other(m) => m,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_login_timeout_kills() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("xodus-login-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("cli.sh");
        let pidfile = dir.join("pid");
        std::fs::write(&script, format!("#!/bin/sh\necho $$ > {}\nexec sleep 30\n", pidfile.display())).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let t = std::time::Instant::now();
        let e = run_login_with(&script, Duration::from_millis(300)).await.unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(2));
        let m = msg(e);
        assert!(m.contains("600") && m.contains("retry in the game"));
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let alive = std::process::Command::new("kill").args(["-0", pid.trim()]).status().unwrap().success();
        assert!(!alive, "login child {pid} still running");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_login_missing_path() {
        let e = run_login_with(Path::new("/nonexistent/xodus-cli"), Duration::from_secs(1))
            .await
            .unwrap_err();
        let m = msg(e);
        assert!(m.contains("/nonexistent/xodus-cli") && m.contains("XODUS_CLI"));
    }

    #[tokio::test]
    async fn run_login_cancelled_exit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("xodus-login-cancel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("cli.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 2\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let e = run_login_with(&script, Duration::from_secs(5)).await.unwrap_err();
        assert!(matches!(e, ServiceError::Cancelled));
        assert_eq!(body(e), "<MSATokenResponse><Error>0x80004004</Error></MSATokenResponse>");
        std::fs::write(&script, "#!/bin/sh\nexit 1\n").unwrap();
        assert!(run_login_with(&script, Duration::from_secs(5)).await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exchange_msa_map_token_error() {
        assert!(matches!(map_token_error(TokenStoreError::NotFound), ServiceError::SignInRequired));
        let io = std::io::Error::other("x");
        assert!(matches!(map_token_error(TokenStoreError::Io(io)), ServiceError::Other(_)));
        assert!(matches!(
            require_legacy(Token::Compact("c".into())),
            Err(ServiceError::SignInRequired)
        ));
    }

    #[test]
    fn exchange_msa_take_security_token() {
        assert_eq!(take_security_token(vec![7]).unwrap(), 7);
        assert!(matches!(take_security_token::<u8>(vec![]), Err(ServiceError::Other(_))));
    }

    #[test]
    fn exchange_msa_success_body_no_device() {
        let b = String::from_utf8(success_body("T".into(), 5, None).unwrap()).unwrap();
        assert!(b.contains("<Token>T</Token>"));
        assert!(b.contains("<DeviceExpiry>0</DeviceExpiry>"));
        assert!(b.contains("<DeviceRps></DeviceRps>") || b.contains("<DeviceRps/>"));
        let b = String::from_utf8(success_body("T".into(), 5, Some(("D".into(), 9))).unwrap()).unwrap();
        assert!(b.contains("<DeviceRps>D</DeviceRps>") && b.contains("<DeviceExpiry>9</DeviceExpiry>"));
    }

    #[test]
    fn exchange_msa_device_failure_is_none() {
        assert!(device_rps(Err(RSTError::HmacKey)).is_none());
    }

    #[test]
    fn exchange_msa_rst_timeout() {
        assert_eq!(rst_timeout(true), Some(Duration::from_secs(20)));
        assert_eq!(rst_timeout(false), None);
    }

    #[test]
    fn run_login_resolve_path() {
        assert_eq!(resolve_cli_path_from(Some("/a/b")), PathBuf::from("/a/b"));
        for v in [Some(""), None] {
            let p = resolve_cli_path_from(v);
            assert_eq!(p.file_name().unwrap(), "xodus-cli");
            assert_eq!(p.parent(), std::env::current_exe().unwrap().parent());
        }
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;

    fn rq(allow_ui: bool) -> MSATokenRequest {
        MSATokenRequest { client_id: "c".into(), allow_ui, msa_full_trust: false }
    }
    fn ok_body() -> Vec<u8> {
        b"<MSATokenResponse><Token>t</Token></MSATokenResponse>".to_vec()
    }
    fn s(b: Vec<u8>) -> String {
        String::from_utf8(b).unwrap()
    }
    fn sir() -> Result<Vec<u8>, ServiceError> {
        Err(ServiceError::SignInRequired)
    }

    #[derive(Clone, Default)]
    struct CapLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for CapLog {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapLog {
        type Writer = CapLog;
        fn make_writer(&'a self) -> CapLog {
            self.clone()
        }
    }

    #[tokio::test]
    async fn handle_msa_no_ui_sign_in() {
        let (ex, lg) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let r = rq(false);
        let out = handle_with(
            &r,
            |_| { ex.fetch_add(1, Ordering::SeqCst); async { sir() } },
            || { lg.fetch_add(1, Ordering::SeqCst); async { Ok(()) } },
            &Mutex::new(0),
        ).await;
        assert!(s(out).contains("0x8004100c"));
        assert_eq!((ex.load(Ordering::SeqCst), lg.load(Ordering::SeqCst)), (1, 0));
    }

    #[tokio::test]
    async fn handle_msa_login_then_ok() {
        let (ex, lg) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let r = rq(true);
        let out = handle_with(
            &r,
            |_| { let n = ex.fetch_add(1, Ordering::SeqCst); async move { if n == 0 { sir() } else { Ok(ok_body()) } } },
            || { lg.fetch_add(1, Ordering::SeqCst); async { Ok(()) } },
            &Mutex::new(0),
        ).await;
        assert_eq!(out, ok_body());
        assert_eq!((ex.load(Ordering::SeqCst), lg.load(Ordering::SeqCst)), (2, 1));
    }

    #[tokio::test]
    async fn handle_msa_second_sign_in_logged() {
        let cap = CapLog::default();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt().with_writer(cap.clone()).finish(),
        );
        let lg = AtomicUsize::new(0);
        let r = rq(true);
        let out = handle_with(
            &r,
            |_| async { sir() },
            || { lg.fetch_add(1, Ordering::SeqCst); async { Ok(()) } },
            &Mutex::new(0),
        ).await;
        assert!(s(out).contains("0x8004100c"));
        assert_eq!(lg.load(Ordering::SeqCst), 1);
        let logged = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("sign-in still required after login"));
    }

    #[tokio::test]
    async fn handle_msa_other_error_no_login() {
        let lg = AtomicUsize::new(0);
        let r = rq(true);
        let out = handle_with(
            &r,
            |_| async { Err(ServiceError::Other("net".into())) },
            || { lg.fetch_add(1, Ordering::SeqCst); async { Ok(()) } },
            &Mutex::new(0),
        ).await;
        assert!(s(out).contains("0x80004005"));
        assert_eq!(lg.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn handle_msa_login_err_no_retry() {
        let ex = AtomicUsize::new(0);
        let r = rq(true);
        let out = handle_with(
            &r,
            |_| { ex.fetch_add(1, Ordering::SeqCst); async { sir() } },
            || async { Err(ServiceError::Other("x".into())) },
            &Mutex::new(0),
        ).await;
        assert!(s(out).contains("0x80004005"));
        assert_eq!(ex.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn handle_msa_concurrent_a() {
        let (ex_b, lg) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let count = Mutex::new(0);
        let (ra, rb) = (rq(true), rq(true));
        let a = handle_with(&ra, |_| async { sir() },
            || { lg.fetch_add(1, Ordering::SeqCst); async { tokio::time::sleep(Duration::from_secs(5)).await; Ok(()) } }, &count);
        let b = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            handle_with(&rb, |_| { ex_b.fetch_add(1, Ordering::SeqCst); async { sir() } },
                || { lg.fetch_add(1, Ordering::SeqCst); async { Ok(()) } }, &count).await
        };
        let (oa, ob) = tokio::join!(a, b);
        assert!(s(oa).contains("0x8004100c") && s(ob).contains("0x8004100c"));
        assert_eq!((lg.load(Ordering::SeqCst), ex_b.load(Ordering::SeqCst)), (1, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn handle_msa_concurrent_b() {
        let (ex_b, lg) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let count = Mutex::new(0);
        let (ra, rb) = (rq(true), rq(true));
        let a = handle_with(&ra, |_| async { sir() },
            || { lg.fetch_add(1, Ordering::SeqCst); async { tokio::time::sleep(Duration::from_secs(5)).await; Err(ServiceError::Other("x".into())) } }, &count);
        let b = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            handle_with(&rb, |_| { ex_b.fetch_add(1, Ordering::SeqCst); async { sir() } },
                || { lg.fetch_add(1, Ordering::SeqCst); async { Ok(()) } }, &count).await
        };
        let (oa, ob) = tokio::join!(a, b);
        assert!(s(oa).contains("0x80004005"));
        assert!(s(ob).contains("0x8004100c"));
        assert_eq!((lg.load(Ordering::SeqCst), ex_b.load(Ordering::SeqCst)), (1, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn handle_msa_concurrent_c() {
        let (ex_b, lg) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let count = Mutex::new(0);
        let (ra, rb) = (rq(true), rq(true));
        let a = handle_with(&ra, |_| async { sir() },
            || { lg.fetch_add(1, Ordering::SeqCst); std::future::pending() }, &count);
        let b = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            handle_with(&rb, |_| { ex_b.fetch_add(1, Ordering::SeqCst); async { sir() } },
                || { lg.fetch_add(1, Ordering::SeqCst); async { Ok(()) } }, &count).await
        };
        let (oa, ob) = tokio::join!(a, b);
        assert!(s(oa).contains("0x80004005"));
        assert!(s(ob).contains("0x8004100c"));
        assert_eq!((lg.load(Ordering::SeqCst), ex_b.load(Ordering::SeqCst)), (1, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn handle_msa_deadline_no_ui() {
        let start = tokio::time::Instant::now();
        let r = rq(false);
        let out = handle_with(&r, |_| std::future::pending(), || async { Ok(()) }, &Mutex::new(0)).await;
        assert!(s(out).contains("0x80004005"));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn handle_msa_deadline_mutex_wait() {
        let start = tokio::time::Instant::now();
        let count = Mutex::new(0);
        let _held = count.lock().await;
        let r = rq(true);
        let out = handle_with(&r, |_| async { sir() }, || async { Ok(()) }, &count).await;
        assert!(s(out).contains("0x80004005"));
        assert!(start.elapsed() < Duration::from_secs(610) + Duration::from_millis(1));
    }

    #[test]
    fn login_and_deadline_constants() {
        assert_eq!(LOGIN_TIMEOUT, Duration::from_secs(600));
        assert_eq!(DEADLINE_UI, Duration::from_secs(610));
    }

    #[tokio::test(start_paused = true)]
    async fn handle_msa_slow_login_then_ok() {
        let ex = AtomicUsize::new(0);
        let start = tokio::time::Instant::now();
        let r = rq(true);
        let out = handle_with(
            &r,
            |_| { let n = ex.fetch_add(1, Ordering::SeqCst); async move { if n == 0 { sir() } else { Ok(ok_body()) } } },
            || async { tokio::time::sleep(Duration::from_secs(300)).await; Ok(()) },
            &Mutex::new(0),
        ).await;
        assert_eq!(out, ok_body());
        assert!(start.elapsed() >= Duration::from_secs(300));
    }

    #[tokio::test]
    async fn handle_msa_login_cancelled() {
        let ex = AtomicUsize::new(0);
        let r = rq(true);
        let out = handle_with(
            &r,
            |_| { ex.fetch_add(1, Ordering::SeqCst); async { sir() } },
            || async { Err(ServiceError::Cancelled) },
            &Mutex::new(0),
        ).await;
        assert!(s(out).contains("0x80004004"));
        assert_eq!(ex.load(Ordering::SeqCst), 1);
    }
}
