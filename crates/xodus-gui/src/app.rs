use eframe::App;

pub struct XodusApp {}

impl XodusApp {
    pub fn new(cc: &eframe::CreationContext) -> Self {
        cc.egui_ctx
            .set_visuals_of(egui::Theme::Dark, crate::theme::xodus_visuals());
        cc.egui_ctx.set_theme(egui::Theme::Dark);
        Self {}
    }
}

impl App for XodusApp {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Welcome to Xodus");
        });
    }
}
