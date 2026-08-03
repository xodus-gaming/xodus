use std::process::ExitCode;
use xodus::tokens::TokenManager;

pub async fn run(tokens: &TokenManager) -> ExitCode {
    match tokens.remove_persistent() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("Failed to logout {err}");
            ExitCode::FAILURE
        }
    }
}
