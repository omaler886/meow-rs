//! Handler-level regression, isolated from other binaries' process globals.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use axum::http::{Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use meow_api::routes::{create_router, AppState};
use meow_common::DnsMode;
use meow_config::raw::RawConfig;
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

const LO: &str = if cfg!(target_os = "macos") {
    "lo0"
} else {
    "lo"
};
const ENV_FILTER: &str = "MiXeD_Target=trace,meow=debug";

struct Stopped(Arc<AtomicBool>);
impl Drop for Stopped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

async fn running_state() -> (Arc<AppState>, Arc<AtomicBool>) {
    // The restart fails on every host, including privileged CI, before
    // creating a real TUN: this device name exceeds the OS name limit.
    let raw: RawConfig = meow_config::parse_raw_yaml(&format!(
        "mode: rule\nlog-level: info\ninterface-name: {LO}\ntun:\n  enable: true\n  device: meow-name-too-long-for-ifnamsiz\n  auto-route: false\n  auto-detect-interface: true\n"
    ))
    .unwrap();
    let resolver = Arc::new(Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        false,
        true,
    ));
    let state = Arc::new(AppState {
        tunnel: Tunnel::new(resolver),
        secret: None,
        config_path: None,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: tokio::sync::broadcast::channel(16).0,
        proxy_providers: Arc::new(DashMap::new()),
        provider_dialer_registry: Default::default(),
        ntp_reconcile: None,
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        rule_provider_refresh: Default::default(),
        proxy_provider_refresh: Default::default(),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
        dns_server: Default::default(),
        ui_storage: Default::default(),
        cors: Default::default(),
    });
    meow_common::set_global_interface_name(Some(LO));
    let binding = meow_common::install_outbound_interface(LO).unwrap();
    binding.commit();
    let stopped = Arc::new(AtomicBool::new(false));
    let stopped_in_task = Arc::clone(&stopped);
    state
        .tunnel
        .set_tun_handle(meow_tunnel::TunHandle {
            task: tokio::spawn(async move {
                let _binding = binding;
                let _stopped = Stopped(stopped_in_task);
                std::future::pending::<()>().await;
            }),
            owner: meow_tunnel::TunOwner::TopLevel,
            core_done: None,
            udp_flows: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
        .await;
    tokio::task::yield_now().await;
    (state, stopped)
}

async fn patch(state: &Arc<AppState>, value: Value) -> (StatusCode, String) {
    let response = create_router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(value.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn assert_tail_unchanged(state: &AppState) {
    let raw = state.raw_config.read();
    assert_eq!(raw.interface_name.as_deref(), Some(LO));
    assert_eq!(raw.log_level.as_deref(), Some("info"));
    assert_eq!(raw.mode.as_deref(), Some("rule"));
    assert_eq!(raw.disable_keep_alive, None);
    assert_eq!(meow_common::global_interface_name().as_deref(), Some(LO));
    assert!(meow_common::outbound_tcp_keepalive().enabled);
}

/// Both failure orders preserve actual logger state and every riding field;
/// a real HTTP interface-only PATCH must reach the TUN restart, unlike the
/// old tail-only implementation. Run with and without listener-tun enabled.
#[tokio::test]
async fn patch_interface_reconciles_and_rolls_back_actual_logging() {
    let actual_filter = Arc::new(Mutex::new(ENV_FILTER.to_owned()));
    let fail_reload = Arc::new(AtomicBool::new(false));
    let reload_filter = Arc::clone(&actual_filter);
    let reload_fail = Arc::clone(&fail_reload);
    let snapshot_filter = Arc::clone(&actual_filter);
    meow_api::log_stream::install_log_reloader_with_rollback(
        move |level| {
            if reload_fail.load(Ordering::SeqCst) {
                *reload_filter.lock() = "partial-reloader-write".to_owned();
                return Err("injected log reloader failure".to_owned());
            }
            *reload_filter.lock() = level.to_owned();
            Ok(())
        },
        move || -> Result<meow_api::log_stream::LogRollbackAction, String> {
            let previous = snapshot_filter.lock().clone();
            let restore_filter = Arc::clone(&snapshot_filter);
            Ok(Box::new(move || {
                *restore_filter.lock() = previous;
                Ok(())
            }))
        },
    );

    // An effective no-op keeps the listener; an unchanged interface does
    // not turn an ordinary successful PATCH into a device restart.
    let (state, stopped) = running_state().await;
    let (status, body) = patch(&state, json!({"interface-name": LO})).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(!stopped.load(Ordering::SeqCst));
    state.tunnel.stop_tun().await;
    assert!(meow_common::outbound_interface().is_none());

    // A fallible reloader runs before any destructive device transition.
    // Its partial mutation is restored by the captured actual-state undo.
    let (state, stopped) = running_state().await;
    fail_reload.store(true, Ordering::SeqCst);
    let (status, body) = patch(
        &state,
        json!({
            "interface-name": "", "log-level": "error", "mode": "direct",
            "disable-keep-alive": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(body.contains("injected log reloader failure"), "{body}");
    assert!(!stopped.load(Ordering::SeqCst));
    assert!(state.raw_config.read().tun.as_ref().unwrap().enable);
    assert_tail_unchanged(&state);
    assert_eq!(actual_filter.lock().as_str(), ENV_FILTER);
    assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
    state.tunnel.stop_tun().await;
    assert!(meow_common::outbound_interface().is_none());
    fail_reload.store(false, Ordering::SeqCst);

    for with_tun_object in [false, true] {
        let (state, stopped) = running_state().await;
        let mut payload = json!({
            "interface-name": "", "log-level": "error", "mode": "direct",
            "disable-keep-alive": true,
        });
        if with_tun_object {
            payload["tun"] = json!({"mtu": 1600});
        }
        let (status, body) = patch(&state, payload).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert!(
            stopped.load(Ordering::SeqCst),
            "interface policy change must reconcile"
        );
        assert!(!state.tunnel.has_tun());
        assert!(!state.raw_config.read().tun.as_ref().unwrap().enable);
        if with_tun_object {
            assert_eq!(
                state.raw_config.read().tun.as_ref().unwrap().mtu,
                Some(1600)
            );
        }
        assert_tail_unchanged(&state);
        assert_eq!(
            actual_filter.lock().as_str(),
            ENV_FILTER,
            "TUN failure must restore the actual filter, not raw log-level: info"
        );
        assert!(meow_common::outbound_interface().is_none());
    }
    meow_common::set_global_interface_name(None);
}
