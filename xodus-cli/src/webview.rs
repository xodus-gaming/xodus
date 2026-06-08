use tao::{
    dpi::{LogicalSize, Size},
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop, EventLoopBuilder},
    platform::run_return::EventLoopExtRunReturn,
    window::WindowBuilder,
};
use wry::{PageLoadEvent, WebViewBuilder};

enum CustomEvent {
    Finish(String),
}

pub struct WebviewCallbackHandler;

impl WebviewCallbackHandler {
    pub async fn call(&self) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let mut token = None;
        let mut event_loop: EventLoop<CustomEvent> = EventLoopBuilder::with_user_event().build();
        let window = WindowBuilder::new()
            .with_resizable(false)
            .with_title("Xodus login")
            .with_inner_size(Size::Logical(LogicalSize::new(500.0, 700.0)))
            .build(&event_loop)
            .unwrap();
        let proxy = event_loop.create_proxy();

        //let clientid = "000000004424da1f".to_string();
        let clientid = "{D6D5A677-0872-4AB0-9442-BB792FCE85C5}".to_string();
        let market = "pl-PL".to_string();
        let url = format!(
            "https://login.live.com/ppsecure/InlineConnect.srf?id=80604&scid=3&mkt={market}&Platform=android2.1.0510.1018&clientid={clientid}"
        );

        let builder = WebViewBuilder::new()
            .with_url(url)
            .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; MSAppHost/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.26100")
            // .with_headers(headermap)
            .with_on_page_load_handler(move |event, url| {
                if matches!(event, PageLoadEvent::Finished)
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
                        let cookies = webview.cookies().unwrap();
                        let mut isfinal = false;
                        for cookie in &cookies {
                            if cookie.name() == "Page" && cookie.value().contains("finalNext") {
                                isfinal = true;
                                break;
                            }
                        }
                        if isfinal {
                            for cookie in cookies {
                                if cookie.name() == "Property" {
                                    token = Some(cookie.value().to_owned());
                                    *control_flow = ControlFlow::Exit;
                                    break;
                                }
                            }
                        }
                    }
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
}
