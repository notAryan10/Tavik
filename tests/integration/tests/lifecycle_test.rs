use std::collections::HashMap;
use std::time::Duration;
use tavik_cli::client::Client;
use tavik_common::protocol::{ProcessStartParams, ProcessStatus};
use tavik_daemon::DaemonServer;
use tempfile::tempdir;

#[tokio::test]
async fn test_daemon_full_lifecycle_and_persistence() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("tavik_test.sock");
    let state_dir = temp_dir.path().join("tavik_state");

    let server = DaemonServer::new(socket_path.clone(), state_dir.clone()).unwrap();

    // Spawn daemon server in background
    let daemon_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Wait briefly for socket to become available
    tokio::time::sleep(Duration::from_millis(150)).await;

    let client = Client::new(socket_path.clone());

    // 1. Verify Ping
    let pong = client.ping().await.expect("ping failed");
    assert_eq!(pong, "pong");

    // 2. Verify Version
    let ver = client.version().await.expect("version failed");
    assert!(ver.get("version").is_some());

    // 3. Verify Info
    let info = client.info().await.expect("info failed");
    assert_eq!(info.engine_name, "TAVIK");
    assert!(!info.os.is_empty());

    // 4. Run a fast task and check completion
    let params = ProcessStartParams {
        command: "/bin/echo".to_string(),
        args: vec!["Integration test running".to_string()],
        env: HashMap::new(),
        working_dir: None,
        name: Some("fast-echo".to_string()),
    };

    let started = client.process_start(params).await.expect("start failed");
    assert_eq!(started.name, "fast-echo");

    // Wait for exit
    tokio::time::sleep(Duration::from_millis(200)).await;

    let inspected = client
        .process_inspect(started.id.clone())
        .await
        .expect("inspect failed");
    assert_eq!(inspected.status, ProcessStatus::Exited { code: 0 });

    // 5. Run a sleeping task and test stopping
    let sleep_params = ProcessStartParams {
        command: "/bin/sleep".to_string(),
        args: vec!["15".to_string()],
        env: HashMap::new(),
        working_dir: None,
        name: Some("sleep-task".to_string()),
    };

    let sleep_task = client
        .process_start(sleep_params)
        .await
        .expect("start sleep failed");
    assert_eq!(sleep_task.status, ProcessStatus::Running);

    let stopped = client
        .process_stop(sleep_task.id.clone(), None)
        .await
        .expect("stop failed");
    assert_eq!(stopped.status, ProcessStatus::Stopped);

    // 6. Test Shutdown
    let shutdown_resp = client.shutdown().await.expect("shutdown failed");
    assert_eq!(shutdown_resp, "shutting down");

    let _ = daemon_task.await;

    // 7. Verify Persistence across Daemon Restarts
    let server2 = DaemonServer::new(socket_path.clone(), state_dir.clone()).unwrap();
    let daemon_task2 = tokio::spawn(async move {
        let _ = server2.run().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    let client2 = Client::new(socket_path);
    let list = client2.process_list().await.expect("list failed");
    assert!(list.len() >= 2);

    let recovered = client2
        .process_inspect(sleep_task.id)
        .await
        .expect("inspect recovered failed");
    assert_eq!(recovered.status, ProcessStatus::Stopped);

    let _ = client2.shutdown().await;
    let _ = daemon_task2.await;
}
