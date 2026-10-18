//! An execution RPC must not outlive the CLI sink that supervises it.
//! Unlike the pooled stream client, this process owns one request and exits
//! on parent-pipe death, closing its socket so the resident cancels the launch.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

pub(crate) fn run(state_base: &Path, payload: Vec<u8>) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(&payload)?;
    if value.get("operation").and_then(serde_json::Value::as_str) != Some("native_bash_execute") {
        return Err("native_bash_client_request_invalid".into());
    }
    if std::env::var_os(crate::PARENT_LIVENESS_FD_ENV).is_none() {
        return Err("native_bash_client_parent_unbound".into());
    }
    let alive = crate::resident_transport_service::resident_parent_liveness()?;
    let state_base = state_base.to_owned();
    let timeout = crate::managed_resident::client_timeout(&payload);
    wait_for_owner(alive, move || {
        crate::managed_resident::client_request(&state_base, &payload, timeout)
    })
}

fn wait_for_owner(
    alive: Arc<AtomicBool>,
    request: impl FnOnce() -> Result<Vec<u8>, String> + Send + 'static,
) -> Result<Vec<u8>, String> {
    if !alive.load(Ordering::Acquire) {
        return Err("native_bash_client_parent_lost".into());
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("guard-bash-owned-client".into())
        .spawn(move || {
            let _ = sender.send(request());
        })
        .map_err(|_| "native_bash_client_unavailable")?;
    loop {
        if !alive.load(Ordering::Acquire) {
            // runtime_cli returns immediately; main exits this dedicated
            // process, closing the worker's socket even during a blocking RPC.
            return Err("native_bash_client_parent_lost".into());
        }
        match receiver.recv_timeout(Duration::from_millis(2)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(_) => return Err("native_bash_client_unavailable".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_owner_never_starts_a_request() {
        let result = wait_for_owner(Arc::new(AtomicBool::new(false)), || {
            panic!("must not start")
        });
        assert_eq!(result.unwrap_err(), "native_bash_client_parent_lost");
    }

    #[test]
    fn owner_loss_interrupts_wait_without_reissuing_the_request() {
        let alive = Arc::new(AtomicBool::new(true));
        let trigger = Arc::clone(&alive);
        let (finish, wait) = mpsc::sync_channel(1);
        let result = wait_for_owner(alive, move || {
            trigger.store(false, Ordering::Release);
            wait.recv().unwrap();
            Ok(vec![1])
        });
        assert_eq!(result.unwrap_err(), "native_bash_client_parent_lost");
        finish.send(()).unwrap();
    }
}
