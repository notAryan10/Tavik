use std::fs;
use std::time::Duration;
use tavik_cli::client::Client;
use tavik_daemon::DaemonServer;
use tavik_runtime::{ContainerExecutor, ContainerStatus, Spec};
use tempfile::tempdir;

#[test]
fn test_oci_bundle_validation_and_executor() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let bundle_dir = temp.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    // 1. Generate default OCI Linux spec and save to bundle
    let spec = Spec::default_linux();
    let config_path = bundle_dir.join("config.json");
    fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

    let executor = ContainerExecutor::new(state_dir).unwrap();
    let container_id = "oci-test-cont-01";

    // 2. Create container
    let state = executor.create(container_id, &bundle_dir).unwrap();
    assert_eq!(state.id, container_id);
    assert_eq!(state.status, ContainerStatus::Created);
    assert_eq!(state.bundle, bundle_dir.canonicalize().unwrap());

    // 3. Query state
    let loaded = executor.load_state(container_id).unwrap();
    assert_eq!(loaded.id, container_id);
    assert_eq!(loaded.status, ContainerStatus::Created);

    // 4. Delete container
    executor.delete(container_id, false).unwrap();
    assert!(executor.load_state(container_id).is_err());
}

#[tokio::test]
async fn test_daemon_oci_container_ipc() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("tavik_oci_test.sock");
    let state_dir = temp_dir.path().join("tavik_state");
    let bundle_dir = temp_dir.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    // Prepare OCI bundle
    let spec = Spec::default_linux();
    let config_path = bundle_dir.join("config.json");
    fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

    let server = DaemonServer::new(socket_path.clone(), state_dir.clone()).unwrap();
    let daemon_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    let client = Client::new(socket_path);

    // 1. Request container create via daemon RPC
    let container_id = "daemon-cont-01".to_string();
    let bundle_path_str = bundle_dir.to_string_lossy().to_string();

    let create_resp = client
        .container_create(container_id.clone(), bundle_path_str)
        .await
        .expect("container_create failed");
    assert_eq!(create_resp["id"], "daemon-cont-01");
    assert_eq!(create_resp["status"], "created");

    // 2. Query container state via daemon RPC
    let state_resp = client
        .container_state(container_id.clone())
        .await
        .expect("container_state failed");
    assert_eq!(state_resp["id"], "daemon-cont-01");
    assert_eq!(state_resp["status"], "created");

    // 3. Delete container via daemon RPC
    let del_resp = client
        .container_delete(container_id.clone(), false)
        .await
        .expect("container_delete failed");
    assert!(del_resp.contains("deleted"));

    let _ = client.shutdown().await;
    let _ = daemon_task.await;
}
