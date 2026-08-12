use std::process::ExitCode;
use xodus::playtime::PlayTimeStore;

pub async fn run(product: Option<String>) -> ExitCode {
    let store = PlayTimeStore::load();

    if store.entries.is_empty() {
        println!("No played time recorded yet.");
        return ExitCode::SUCCESS;
    }

    if let Some(prod) = product {
        let seconds = store.get_playtime(&prod);
        if seconds == 0 {
            println!("No playtime recorded for '{}'", prod);
        } else {
            let formatted = PlayTimeStore::format_duration(seconds);
            println!("{}: {}", prod, formatted);
        }
    } else {
        println!("Game Playtime Summary:");
        println!("{:<36} | {:<15} | {:<20}", "Content ID", "Played Time", "Last Played");
        println!("{:-<36}-+-{:-<15}-+-{:-<20}", "", "", "");

        let mut sorted_entries: Vec<_> = store.entries.values().collect();
        sorted_entries.sort_by(|a, b| b.total_seconds.cmp(&a.total_seconds));

        for entry in sorted_entries {
            let duration = PlayTimeStore::format_duration(entry.total_seconds);
            let last_played = entry
                .last_played_at
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "N/A".to_string());

            println!("{:<36} | {:<15} | {:<20}", entry.content_id, duration, last_played);
        }
    }

    ExitCode::SUCCESS
}
