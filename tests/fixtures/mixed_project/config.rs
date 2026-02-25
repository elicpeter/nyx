use std::env;
use std::fs;
use std::process::Command;

/// Infrastructure provisioning tool — Rust core.
/// Reads infrastructure config from environment and executes provisioning commands.

struct InfraConfig {
    provider: String,
    region: String,
    ssh_key_path: String,
    cluster_name: String,
}

fn load_infra_config() -> InfraConfig {
    InfraConfig {
        provider: env::var("CLOUD_PROVIDER").unwrap(),
        region: env::var("CLOUD_REGION").unwrap(),
        ssh_key_path: env::var("SSH_KEY_PATH").expect("SSH_KEY_PATH required"),
        cluster_name: env::var("CLUSTER_NAME").unwrap(),
    }
}

/// Provisions a new cluster by shelling out to the provider CLI.
/// VULN: env var flows into Command (command injection)
fn provision_cluster() {
    let cfg = load_infra_config();
    let cmd = format!(
        "{}-cli create-cluster --name {} --region {} --ssh-key {}",
        cfg.provider, cfg.cluster_name, cfg.region, cfg.ssh_key_path
    );
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("provisioning failed");

    if !output.status.success() {
        panic!("Cluster provisioning failed: {}", String::from_utf8_lossy(&output.stderr));
    }
}

/// Reads a Terraform state file and applies changes.
/// VULN: file contents flow into Command
fn apply_terraform() {
    let state = fs::read_to_string("/etc/terraform/main.tf").unwrap();
    let workspace = state.lines()
        .find(|l| l.starts_with("workspace"))
        .unwrap_or("default");
    Command::new("terraform")
        .arg("apply")
        .arg("-auto-approve")
        .arg("-var")
        .arg(format!("workspace={}", workspace))
        .status()
        .unwrap();
}

/// Destroys infrastructure — reads target from env.
/// VULN: env var flows into Command
fn destroy_cluster() {
    let cluster = env::var("DESTROY_TARGET").unwrap();
    Command::new("sh")
        .arg("-c")
        .arg(format!("kubectl delete cluster {}", cluster))
        .status()
        .expect("destroy failed");
}
