use egui::{Color32, Visuals};

pub fn xodus_visuals() -> Visuals {
    Visuals {
        dark_mode: true,
        window_fill: Color32::from_rgb(26, 26, 30),
        panel_fill: Color32::from_rgb(26, 26, 30),
        ..Default::default()
    }
}
