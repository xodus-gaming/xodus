use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod app;
mod theme;

fn main() {
    let filter = tracing_subscriber::EnvFilter::from_env("XODUS_LOG");
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(filter))
        .init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_min_inner_size([300.0, 220.0]),
        ..Default::default()
    };

    eframe::run_native(
        "io.github.xodus-gaming.xodus",
        native_options,
        Box::new(|cc| Ok(Box::new(app::XodusApp::new(cc)))),
    )
    .expect("Eframe failure to start Xodus");
}
