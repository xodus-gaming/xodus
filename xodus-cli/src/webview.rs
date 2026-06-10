use tao::{
    dpi::{LogicalSize, Size},
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop, EventLoopBuilder},
    platform::run_return::EventLoopExtRunReturn,
    window::WindowBuilder,
};
use wry::http::{HeaderMap, HeaderValue};
use wry::{PageLoadEvent, WebViewBuilder};
use xodus::models::live::DAProperty;

enum CustomEvent {
    HostGetContext(String),
    Finish(String),
    IpcCallback(DAProperty),
}

pub async fn login_client(
    client_id: String,
    market: String,
) -> Result<Option<DAProperty>, Box<dyn std::error::Error>> {
    let mut token = None;
    let mut event_loop: EventLoop<CustomEvent> = EventLoopBuilder::with_user_event().build();
    let window = WindowBuilder::new()
        .with_resizable(false)
        .with_title("Xodus login")
        .with_inner_size(Size::Logical(LogicalSize::new(500.0, 700.0)))
        .build(&event_loop)
        .unwrap();
    let proxy = event_loop.create_proxy();
    let uid = uuid::Uuid::new_v4();
    let url = format!(
        "https://login.live.com/ppsecure/InlineLogin.srf?id=80604&scid=3&mkt={market}&Platform=Windows10&clientid={client_id}&hosted=1"
    );

    let mut headers = HeaderMap::new();
    headers.insert("cxh-capabilities", HeaderValue::from_static(r#"{"PrivatePropertyBag":1,"PasswordlessConnect":1,"PreferAssociate":0,"ChromelessUI":1}"#));
    headers.insert(
        "cxh-correlationId",
        HeaderValue::from_str(&format!("{uid}")).unwrap(),
    );
    headers.insert("cxh-msaBinaryVersion", HeaderValue::from_static(r#"55"#));
    headers.insert(
        "cxh-identityClientBinaryVersion",
        HeaderValue::from_static(r#"3"#),
    );
    headers.insert(
        "cxh-osVersionInfo",
        HeaderValue::from_static(
            r#"{"platformId":2,"majorVersion":10,"minorVersion":0,"buildNumber":26100}"#,
        ),
    );
    headers.insert(
        "cxh-platform",
        HeaderValue::from_static(r#"CloudExperienceHost.Platform.DESKTOP"#),
    );
    headers.insert("cxh-protocol", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert("cxh-source", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert(
        "hostApp",
        HeaderValue::from_static(r#"CloudExperienceHost"#),
    );

    let headermap: HeaderMap = headers.try_into().unwrap();

    let proxy_ipc = proxy.clone();
    let builder = WebViewBuilder::new()
            .with_url(url)
            .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; MSAppHost/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.26100")
            .with_headers(headermap)
            .with_initialization_script("window.external = {notify: window.ipc.postMessage }")
            .with_ipc_handler(move |request| {
                println!("{request:?}");
                let payload = serde_json::from_str::<DAProperty>(request.body());
                if let Ok(data) = payload {
                    proxy_ipc.send_event(CustomEvent::IpcCallback(data)).ok();
                } else {
                    let parsed: serde_json::Value = serde_json::from_str(request.body()).unwrap();
                    if parsed.get("type").unwrap().as_str() == Some("invoke") {
                        let name = parsed.get("value").unwrap().get("name").unwrap().as_str();
                        match name {
                            Some("CloudExperienceHost.getContext") => { 
                                let ctx =  parsed.get("value").unwrap().get("context").unwrap().as_str().unwrap().to_string();
                                proxy_ipc.send_event(CustomEvent::HostGetContext(ctx)).ok(); },
                            _ => ()
                        }
                    }
                }
            })
            .with_on_page_load_handler(move |event, url| {
                if matches!(event, PageLoadEvent::Finished) && url.starts_with("https://login.live.com/ppsecure/post.srf")
                {
                    proxy.send_event(CustomEvent::Finish(url)).ok();
                }
            });

    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        builder.build_gtk(window.default_vbox().unwrap()).unwrap()
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window).unwrap();

    event_loop.run_return(|event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(CustomEvent::Finish(url)) => {
                if !url.contains("access_denied") {
                    _ = webview
                        .evaluate_script("window.ipc.postMessage(JSON.stringify(ServerData))");
                }
            }
            Event::UserEvent(CustomEvent::HostGetContext(ctx)) => {
                _ = webview.evaluate_script(&format!(r#"window["CloudExperienceHost.Bridge.dispatchMessage"](JSON.stringify({{"type": "callback", "value": {{ "name": "CloudExperienceHost.getContext", "args": ["CloudExperienceHost", "TokenBroker", "TokenBroker", "{{\"PrivatePropertyBag\":1,\"PasswordlessConnect\":1,\"PreferAssociate\":0,\"ChromelessUI\":1}}"], "context": "{ctx}"}}}}))"#));
            }
            Event::UserEvent(CustomEvent::IpcCallback(data)) => {
                token = Some(data);
                *control_flow = ControlFlow::Exit;
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }

            _ => (),
        }
    });

    Ok(token)
}
