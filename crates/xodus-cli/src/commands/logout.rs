use std::process::ExitCode;
use xodus::tokens::TokenManager;

pub async fn run(tokens: &TokenManager, device: bool) -> ExitCode {
    if device && tokens.remove_device_license().is_err() {
        return ExitCode::FAILURE;
    }
    match tokens.remove_persistent() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("Failed to logout {err}");
            ExitCode::FAILURE
        }
    }
}
