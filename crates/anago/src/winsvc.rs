//! The Windows service entry (§11.1 결정 3) — what `sc.exe` starts.
//!
//! `anago server run --service` hands control to the SCM dispatcher;
//! the service main then runs the same hub loop systemd runs on Linux.
//! Stop/shutdown exit the process — abrupt, and safe by construction:
//! every state write in this program is atomic (fsutil), so there is
//! nothing a kill can tear.
#![cfg(windows)]

use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::service::SERVICE_NAME;

define_windows_service!(ffi_service_main, service_main);

/// Hands this process to the SCM. Never returns to the caller: the
/// dispatcher blocks until the service stops, and a failure to connect
/// (someone typed `--service` in a console) is reported and exits.
pub fn run() -> ! {
    if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        eprintln!(
            "anago: --service is for the Windows service manager, not a console \
             (start the hub with `sc start {SERVICE_NAME}`, or run `anago server run` \
             without the flag): {e}"
        );
        std::process::exit(2);
    }
    std::process::exit(0);
}

fn service_main(_args: Vec<std::ffi::OsString>) {
    let handler = service_control_handler::register(SERVICE_NAME, |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // Atomic writes make an abrupt exit safe (module docs).
            std::process::exit(0);
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    });
    let Ok(handle) = handler else {
        return;
    };
    let status = |state: ServiceState, code: u32| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    let _ = handle.set_service_status(status(ServiceState::Running, 0));

    let result = crate::serve::run(
        &crate::paths::default_server_root(),
        &crate::paths::default_wg_dir(),
    );
    if let Err(e) = &result {
        // A service has no console — leave the reason where a person
        // can find it (§11.1: the note printed by init names this file).
        let log = crate::paths::default_server_root().join("service.log");
        let _ = std::fs::write(&log, format!("anago server run failed: {e}\n"));
    }
    let _ = handle.set_service_status(status(
        ServiceState::Stopped,
        if result.is_ok() { 0 } else { 1 },
    ));
}
