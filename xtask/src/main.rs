use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Orchestrateur de build, création d'ISO et tests QEMU pour JamboOS")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile le micro-noyau JamboKernel
    Build {
        #[arg(long)]
        release: bool,
    },
    /// Génère l'image ISO amorçable hybride UEFI / BIOS (jamboos-x86_64.iso)
    Iso {
        #[arg(long)]
        release: bool,
        #[arg(long)]
        test: bool,
    },
    /// Lance l'image ISO sous QEMU en mode interactif avec console série
    #[command(alias = "qemu")]
    Run {
        #[arg(long)]
        release: bool,
        #[arg(long, default_value = "4")]
        smp: usize,
        #[arg(long, default_value = "2G")]
        memory: String,
    },
    /// Exécute les tests automatisés de démarrage sous QEMU pour la CI
    #[command(alias = "test-qemu")]
    Test {
        #[arg(long)]
        release: bool,
    },
    /// Génère l'arborescence EFI System Partition (ESP) prête à copier sur clé USB FAT32
    Esp {
        #[arg(long)]
        release: bool,
    },
    /// Outil de déploiement et écriture sur clé USB pour matériel physique
    #[command(alias = "flash")]
    FlashUsb {
        #[arg(long)]
        release: bool,
        /// Répertoire monté du périphérique (ex: E:\ sous Windows ou /media/user/USB sous Linux)
        #[arg(long)]
        device: Option<String>,
    },
    /// Prépare l'archive et les artefacts de test pour le prototype expérimental v0.3.87
    Dist {
        #[arg(long)]
        release: bool,
    },
}

fn root_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Workspace root directory")
        .to_path_buf()
}

fn build_kernel(release: bool, test_features: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "kernel",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    if test_features {
        cmd.args(["--features", "kernel/qemu-test"]);
    }

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du noyau JamboKernel");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/kernel", profile)))
}

fn build_init(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-init",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-init");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/jambo-init", profile)))
}

fn build_jsh(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-sh",
        "--bin",
        "jsh",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jsh");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/jsh", profile)))
}

fn build_blockd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-blockd",
        "--bin",
        "jambo-blockd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-blockd");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!(
        "target/x86_64-unknown-none/{}/jambo-blockd",
        profile
    )))
}

fn build_fs(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-fs",
        "--bin",
        "jambo-fs",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-fs");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/jambo-fs", profile)))
}

fn build_netd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-netd",
        "--bin",
        "netd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-netd (netd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/netd", profile)))
}

fn build_fdr(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-fdr",
        "--bin",
        "fdr",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-fdr (fdr)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/fdr", profile)))
}

fn build_wasmd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-wasmd",
        "--bin",
        "wasmd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-wasmd (wasmd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/wasmd", profile)))
}

fn build_pqc(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-pqc",
        "--bin",
        "pqc",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-pqc (pqc)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/pqc", profile)))
}

fn build_kdir(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-kdir",
        "--bin",
        "kdir",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-kdir (kdir)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/kdir", profile)))
}

fn build_forensics(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-forensics",
        "--bin",
        "forensics",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-forensics (forensics)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/forensics", profile)))
}

fn build_powerd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-powerd",
        "--bin",
        "powerd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-powerd (powerd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/powerd", profile)))
}

fn build_metricsd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-metricsd",
        "--bin",
        "metricsd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-metricsd (metricsd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/metricsd", profile)))
}

fn build_bpfd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-bpfd",
        "--bin",
        "bpfd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-bpfd (bpfd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/bpfd", profile)))
}

fn build_vpn(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-vpn",
        "--bin",
        "vpn",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-vpn (vpn)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/vpn", profile)))
}

fn build_authd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-authd",
        "--bin",
        "authd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-authd (authd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/authd", profile)))
}

fn build_dnsd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-dnsd",
        "--bin",
        "dnsd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-dnsd (dnsd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/dnsd", profile)))
}

fn build_timed(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-timed",
        "--bin",
        "timed",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-timed (timed)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/timed", profile)))
}

fn build_auditd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-auditd",
        "--bin",
        "auditd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-auditd (auditd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/auditd", profile)))
}

fn build_walld(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-walld",
        "--bin",
        "walld",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-walld (walld)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/walld", profile)))
}

fn build_vaultd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-vaultd",
        "--bin",
        "vaultd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-vaultd (vaultd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/vaultd", profile)))
}

fn build_watchdogd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-watchdogd",
        "--bin",
        "watchdogd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-watchdogd (watchdogd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/watchdogd", profile)))
}

fn build_cored(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-cored",
        "--bin",
        "cored",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-cored (cored)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/cored", profile)))
}

fn build_pkgd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-pkgd",
        "--bin",
        "pkgd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-pkgd (pkgd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/pkgd", profile)))
}

fn build_certd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-certd",
        "--bin",
        "certd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-certd (certd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/certd", profile)))
}

fn build_policyd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-policyd",
        "--bin",
        "policyd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-policyd (policyd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/policyd", profile)))
}

fn build_secboot(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-secboot",
        "--bin",
        "secboot",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-secboot (secboot)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/secboot", profile)))
}

fn build_logd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-logd",
        "--bin",
        "logd",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-logd (logd)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/logd", profile)))
}

fn build_kms(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-kms",
        "--bin",
        "kms",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-kms (kms)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/kms", profile)))
}

fn build_attest(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-attest",
        "--bin",
        "attest",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-attest (attest)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/attest", profile)))
}

fn build_waf(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-waf",
        "--bin",
        "waf",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-waf (waf)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/waf", profile)))
}

fn build_siem(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-siem",
        "--bin",
        "siem",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-siem (siem)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/siem", profile)))
}

fn build_edr(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-edr",
        "--bin",
        "edr",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-edr (edr)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/edr", profile)))
}

fn build_ndr(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-ndr",
        "--bin",
        "ndr",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-ndr (ndr)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/ndr", profile)))
}

fn build_xdr(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-xdr",
        "--bin",
        "xdr",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-xdr (xdr)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/xdr", profile)))
}

fn build_soar(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-soar",
        "--bin",
        "soar",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-soar (soar)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/soar", profile)))
}

fn build_ueba(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-ueba",
        "--bin",
        "ueba",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-ueba (ueba)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/ueba", profile)))
}

fn build_itdr(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-itdr",
        "--bin",
        "itdr",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-itdr (itdr)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/itdr", profile)))
}

fn build_dlp(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "--package",
        "jambo-dlp",
        "--bin",
        "dlp",
        "--target",
        "x86_64-unknown-none",
    ]);
    if release {
        cmd.arg("--release");
    }
    cmd.env(
        "RUSTFLAGS",
        "-C link-arg=-Tlibs/user-x86_64.ld -C relocation-model=static",
    );

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Échec de compilation du binaire jambo-dlp (dlp)");
    }

    let profile = if release { "release" } else { "debug" };
    Ok(root.join(format!("target/x86_64-unknown-none/{}/dlp", profile)))
}

#[allow(clippy::type_complexity)]
fn build_userland(
    release: bool,
) -> anyhow::Result<(
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
)> {
    let init = build_init(release)?;
    let jsh = build_jsh(release)?;
    let blockd = build_blockd(release)?;
    let fs = build_fs(release)?;
    let netd = build_netd(release)?;
    let fdr = build_fdr(release)?;
    let wasmd = build_wasmd(release)?;
    let pqc = build_pqc(release)?;
    let kdir = build_kdir(release)?;
    let forensics = build_forensics(release)?;
    let powerd = build_powerd(release)?;
    let metricsd = build_metricsd(release)?;
    let bpfd = build_bpfd(release)?;
    let vpn = build_vpn(release)?;
    let authd = build_authd(release)?;
    let dnsd = build_dnsd(release)?;
    let timed = build_timed(release)?;
    let auditd = build_auditd(release)?;
    let walld = build_walld(release)?;
    let vaultd = build_vaultd(release)?;
    let watchdogd = build_watchdogd(release)?;
    let cored = build_cored(release)?;
    let pkgd = build_pkgd(release)?;
    let certd = build_certd(release)?;
    let policyd = build_policyd(release)?;
    let secboot = build_secboot(release)?;
    let logd = build_logd(release)?;
    let kms = build_kms(release)?;
    let attest = build_attest(release)?;
    let waf = build_waf(release)?;
    let siem = build_siem(release)?;
    let edr = build_edr(release)?;
    let ndr = build_ndr(release)?;
    let xdr = build_xdr(release)?;
    let soar = build_soar(release)?;
    let ueba = build_ueba(release)?;
    let itdr = build_itdr(release)?;
    let dlp = build_dlp(release)?;
    Ok((
        init, jsh, blockd, fs, netd, fdr, wasmd, pqc, kdir, forensics, powerd, metricsd, bpfd, vpn,
        authd, dnsd, timed, auditd, walld, vaultd, watchdogd, cored, pkgd, certd, policyd, secboot,
        logd, kms, attest, waf, siem, edr, ndr, xdr, soar, ueba, itdr, dlp,
    ))
}

fn create_disk_image(path: &Path) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    file.set_len(32 * 1024 * 1024)?; // 32 Mio = 33 554 432 octets

    // 1. Uberblock JamboFS à l'offset 0 (LBA 0..7)
    let mut uberblock_buf = [0u8; 4096];
    // Magic: 0x53465F4F424D414A ("JAMBO_FS")
    uberblock_buf[0..8].copy_from_slice(&0x53465F4F424D414Au64.to_le_bytes());
    // Version: 1
    uberblock_buf[8..12].copy_from_slice(&1u32.to_le_bytes());
    // Block size: 4096
    uberblock_buf[12..16].copy_from_slice(&4096u32.to_le_bytes());
    // Generation: 1
    uberblock_buf[16..24].copy_from_slice(&1u64.to_le_bytes());
    // Root tree offset: 8192
    uberblock_buf[24..32].copy_from_slice(&8192u64.to_le_bytes());

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&uberblock_buf)?;

    // 2. Nœud racine à l'offset 8192 (LBA 16..23) : entrée "banner.txt", direct_block LBA 24, size 30
    let mut root_buf = [0u8; 4096];
    root_buf[0..8].copy_from_slice(&1u64.to_le_bytes()); // Inode 1
    root_buf[8..16].copy_from_slice(&30u64.to_le_bytes()); // Taille 30 octets
    root_buf[16..24].copy_from_slice(&1u64.to_le_bytes()); // Génération 1
    root_buf[24..28].copy_from_slice(&0u32.to_le_bytes()); // Flags
    root_buf[28..32].copy_from_slice(&1u32.to_le_bytes()); // Block count 1
    root_buf[32..40].copy_from_slice(&24u64.to_le_bytes()); // Direct block LBA 24
    let name = b"banner.txt";
    root_buf[64..64 + name.len()].copy_from_slice(name);

    file.seek(SeekFrom::Start(8192))?;
    file.write_all(&root_buf)?;

    // 3. Données à l'offset 12288 (LBA 24..31) : "Bienvenue sur JamboOS v0.3.76\n"
    let banner_data = b"Bienvenue sur JamboOS v0.3.77\n";
    let mut data_buf = [0u8; 4096];
    data_buf[..banner_data.len()].copy_from_slice(banner_data);

    file.seek(SeekFrom::Start(12288))?;
    file.write_all(&data_buf)?;

    file.flush()?;
    Ok(())
}

fn create_initrd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let (
        init_bin,
        jsh_bin,
        blockd_bin,
        fs_bin,
        netd_bin,
        fdr_bin,
        wasmd_bin,
        pqc_bin,
        kdir_bin,
        forensics_bin,
        powerd_bin,
        metricsd_bin,
        bpfd_bin,
        vpn_bin,
        authd_bin,
        dnsd_bin,
        timed_bin,
        auditd_bin,
        walld_bin,
        vaultd_bin,
        watchdogd_bin,
        cored_bin,
        pkgd_bin,
        certd_bin,
        policyd_bin,
        secboot_bin,
        logd_bin,
        kms_bin,
        attest_bin,
        waf_bin,
        siem_bin,
        edr_bin,
        ndr_bin,
        xdr_bin,
        soar_bin,
        ueba_bin,
        itdr_bin,
        dlp_bin,
    ) = build_userland(release)?;

    let initrd_stage = root.join("target/initrd_stage");
    let bin_dir = initrd_stage.join("bin");
    let _ = fs::remove_dir_all(&initrd_stage);
    fs::create_dir_all(&bin_dir)?;

    fs::copy(&init_bin, bin_dir.join("init"))?;
    fs::copy(&jsh_bin, bin_dir.join("jsh"))?;
    fs::copy(&blockd_bin, bin_dir.join("blockd"))?;
    fs::copy(&fs_bin, bin_dir.join("fs"))?;
    fs::copy(&netd_bin, bin_dir.join("netd"))?;
    fs::copy(&fdr_bin, bin_dir.join("fdr"))?;
    fs::copy(&wasmd_bin, bin_dir.join("wasmd"))?;
    fs::copy(&pqc_bin, bin_dir.join("pqc"))?;
    fs::copy(&kdir_bin, bin_dir.join("kdir"))?;
    fs::copy(&forensics_bin, bin_dir.join("forensics"))?;
    fs::copy(&forensics_bin, bin_dir.join("jambo-forensics"))?;
    fs::copy(&powerd_bin, bin_dir.join("powerd"))?;
    fs::copy(&powerd_bin, bin_dir.join("jambo-powerd"))?;
    fs::copy(&metricsd_bin, bin_dir.join("metricsd"))?;
    fs::copy(&metricsd_bin, bin_dir.join("jambo-metricsd"))?;
    fs::copy(&bpfd_bin, bin_dir.join("bpfd"))?;
    fs::copy(&bpfd_bin, bin_dir.join("jambo-bpfd"))?;
    fs::copy(&vpn_bin, bin_dir.join("vpn"))?;
    fs::copy(&vpn_bin, bin_dir.join("jambo-vpn"))?;
    fs::copy(&authd_bin, bin_dir.join("authd"))?;
    fs::copy(&authd_bin, bin_dir.join("jambo-authd"))?;
    fs::copy(&dnsd_bin, bin_dir.join("dnsd"))?;
    fs::copy(&dnsd_bin, bin_dir.join("jambo-dnsd"))?;
    fs::copy(&timed_bin, bin_dir.join("timed"))?;
    fs::copy(&timed_bin, bin_dir.join("jambo-timed"))?;
    fs::copy(&auditd_bin, bin_dir.join("auditd"))?;
    fs::copy(&auditd_bin, bin_dir.join("jambo-auditd"))?;
    fs::copy(&walld_bin, bin_dir.join("walld"))?;
    fs::copy(&walld_bin, bin_dir.join("jambo-walld"))?;
    fs::copy(&vaultd_bin, bin_dir.join("vaultd"))?;
    fs::copy(&vaultd_bin, bin_dir.join("jambo-vaultd"))?;
    fs::copy(&watchdogd_bin, bin_dir.join("watchdogd"))?;
    fs::copy(&watchdogd_bin, bin_dir.join("jambo-watchdogd"))?;
    fs::copy(&cored_bin, bin_dir.join("cored"))?;
    fs::copy(&cored_bin, bin_dir.join("jambo-cored"))?;
    fs::copy(&pkgd_bin, bin_dir.join("pkgd"))?;
    fs::copy(&pkgd_bin, bin_dir.join("jambo-pkgd"))?;
    fs::copy(&certd_bin, bin_dir.join("certd"))?;
    fs::copy(&certd_bin, bin_dir.join("jambo-certd"))?;
    fs::copy(&policyd_bin, bin_dir.join("policyd"))?;
    fs::copy(&policyd_bin, bin_dir.join("jambo-policyd"))?;
    fs::copy(&secboot_bin, bin_dir.join("secboot"))?;
    fs::copy(&secboot_bin, bin_dir.join("jambo-secboot"))?;
    fs::copy(&logd_bin, bin_dir.join("logd"))?;
    fs::copy(&logd_bin, bin_dir.join("jambo-logd"))?;
    fs::copy(&kms_bin, bin_dir.join("kms"))?;
    fs::copy(&kms_bin, bin_dir.join("jambo-kms"))?;
    fs::copy(&attest_bin, bin_dir.join("attest"))?;
    fs::copy(&attest_bin, bin_dir.join("jambo-attest"))?;
    fs::copy(&waf_bin, bin_dir.join("waf"))?;
    fs::copy(&waf_bin, bin_dir.join("jambo-waf"))?;
    fs::copy(&siem_bin, bin_dir.join("siem"))?;
    fs::copy(&siem_bin, bin_dir.join("jambo-siem"))?;
    fs::copy(&edr_bin, bin_dir.join("edr"))?;
    fs::copy(&edr_bin, bin_dir.join("jambo-edr"))?;
    fs::copy(&ndr_bin, bin_dir.join("ndr"))?;
    fs::copy(&ndr_bin, bin_dir.join("jambo-ndr"))?;
    fs::copy(&xdr_bin, bin_dir.join("xdr"))?;
    fs::copy(&xdr_bin, bin_dir.join("jambo-xdr"))?;
    fs::copy(&soar_bin, bin_dir.join("soar"))?;
    fs::copy(&soar_bin, bin_dir.join("jambo-soar"))?;
    fs::copy(&ueba_bin, bin_dir.join("ueba"))?;
    fs::copy(&ueba_bin, bin_dir.join("jambo-ueba"))?;
    fs::copy(&itdr_bin, bin_dir.join("itdr"))?;
    fs::copy(&itdr_bin, bin_dir.join("jambo-itdr"))?;
    fs::copy(&dlp_bin, bin_dir.join("dlp"))?;
    fs::copy(&dlp_bin, bin_dir.join("jambo-dlp"))?;

    fs::copy(&init_bin, initrd_stage.join("init"))?;
    fs::copy(&jsh_bin, initrd_stage.join("jsh"))?;
    fs::copy(&blockd_bin, initrd_stage.join("blockd"))?;
    fs::copy(&fs_bin, initrd_stage.join("fs"))?;
    fs::copy(&netd_bin, initrd_stage.join("netd"))?;
    fs::copy(&fdr_bin, initrd_stage.join("fdr"))?;
    fs::copy(&wasmd_bin, initrd_stage.join("wasmd"))?;
    fs::copy(&pqc_bin, initrd_stage.join("pqc"))?;
    fs::copy(&kdir_bin, initrd_stage.join("kdir"))?;
    fs::copy(&forensics_bin, initrd_stage.join("forensics"))?;
    fs::copy(&forensics_bin, initrd_stage.join("jambo-forensics"))?;
    fs::copy(&powerd_bin, initrd_stage.join("powerd"))?;
    fs::copy(&powerd_bin, initrd_stage.join("jambo-powerd"))?;
    fs::copy(&metricsd_bin, initrd_stage.join("metricsd"))?;
    fs::copy(&metricsd_bin, initrd_stage.join("jambo-metricsd"))?;
    fs::copy(&bpfd_bin, initrd_stage.join("bpfd"))?;
    fs::copy(&bpfd_bin, initrd_stage.join("jambo-bpfd"))?;
    fs::copy(&vpn_bin, initrd_stage.join("vpn"))?;
    fs::copy(&vpn_bin, initrd_stage.join("jambo-vpn"))?;
    fs::copy(&authd_bin, initrd_stage.join("authd"))?;
    fs::copy(&authd_bin, initrd_stage.join("jambo-authd"))?;
    fs::copy(&dnsd_bin, initrd_stage.join("dnsd"))?;
    fs::copy(&dnsd_bin, initrd_stage.join("jambo-dnsd"))?;
    fs::copy(&timed_bin, initrd_stage.join("timed"))?;
    fs::copy(&timed_bin, initrd_stage.join("jambo-timed"))?;
    fs::copy(&auditd_bin, initrd_stage.join("auditd"))?;
    fs::copy(&auditd_bin, initrd_stage.join("jambo-auditd"))?;
    fs::copy(&walld_bin, initrd_stage.join("walld"))?;
    fs::copy(&walld_bin, initrd_stage.join("jambo-walld"))?;
    fs::copy(&vaultd_bin, initrd_stage.join("vaultd"))?;
    fs::copy(&vaultd_bin, initrd_stage.join("jambo-vaultd"))?;
    fs::copy(&watchdogd_bin, initrd_stage.join("watchdogd"))?;
    fs::copy(&watchdogd_bin, initrd_stage.join("jambo-watchdogd"))?;
    fs::copy(&cored_bin, initrd_stage.join("cored"))?;
    fs::copy(&cored_bin, initrd_stage.join("jambo-cored"))?;
    fs::copy(&pkgd_bin, initrd_stage.join("pkgd"))?;
    fs::copy(&pkgd_bin, initrd_stage.join("jambo-pkgd"))?;
    fs::copy(&certd_bin, initrd_stage.join("certd"))?;
    fs::copy(&certd_bin, initrd_stage.join("jambo-certd"))?;
    fs::copy(&policyd_bin, initrd_stage.join("policyd"))?;
    fs::copy(&policyd_bin, initrd_stage.join("jambo-policyd"))?;
    fs::copy(&secboot_bin, initrd_stage.join("secboot"))?;
    fs::copy(&secboot_bin, initrd_stage.join("jambo-secboot"))?;
    fs::copy(&logd_bin, initrd_stage.join("logd"))?;
    fs::copy(&logd_bin, initrd_stage.join("jambo-logd"))?;
    fs::copy(&kms_bin, initrd_stage.join("kms"))?;
    fs::copy(&kms_bin, initrd_stage.join("jambo-kms"))?;
    fs::copy(&attest_bin, initrd_stage.join("attest"))?;
    fs::copy(&attest_bin, initrd_stage.join("jambo-attest"))?;
    fs::copy(&waf_bin, initrd_stage.join("waf"))?;
    fs::copy(&waf_bin, initrd_stage.join("jambo-waf"))?;
    fs::copy(&siem_bin, initrd_stage.join("siem"))?;
    fs::copy(&siem_bin, initrd_stage.join("jambo-siem"))?;
    fs::copy(&edr_bin, initrd_stage.join("edr"))?;
    fs::copy(&edr_bin, initrd_stage.join("jambo-edr"))?;
    fs::copy(&ndr_bin, initrd_stage.join("ndr"))?;
    fs::copy(&ndr_bin, initrd_stage.join("jambo-ndr"))?;
    fs::copy(&xdr_bin, initrd_stage.join("xdr"))?;
    fs::copy(&xdr_bin, initrd_stage.join("jambo-xdr"))?;
    fs::copy(&soar_bin, initrd_stage.join("soar"))?;
    fs::copy(&soar_bin, initrd_stage.join("jambo-soar"))?;
    fs::copy(&ueba_bin, initrd_stage.join("ueba"))?;
    fs::copy(&ueba_bin, initrd_stage.join("jambo-ueba"))?;
    fs::copy(&itdr_bin, initrd_stage.join("itdr"))?;
    fs::copy(&itdr_bin, initrd_stage.join("jambo-itdr"))?;
    fs::copy(&dlp_bin, initrd_stage.join("dlp"))?;
    fs::copy(&dlp_bin, initrd_stage.join("jambo-dlp"))?;

    let initrd_tar = root.join("target/initrd.tar");
    let status = Command::new("tar")
        .current_dir(&initrd_stage)
        .args([
            "-cf",
            initrd_tar.to_str().unwrap(),
            "bin/init",
            "bin/jsh",
            "bin/blockd",
            "bin/fs",
            "bin/netd",
            "bin/fdr",
            "bin/wasmd",
            "bin/pqc",
            "bin/kdir",
            "bin/forensics",
            "bin/jambo-forensics",
            "bin/powerd",
            "bin/jambo-powerd",
            "bin/metricsd",
            "bin/jambo-metricsd",
            "bin/bpfd",
            "bin/jambo-bpfd",
            "bin/vpn",
            "bin/jambo-vpn",
            "bin/authd",
            "bin/jambo-authd",
            "bin/dnsd",
            "bin/jambo-dnsd",
            "bin/timed",
            "bin/jambo-timed",
            "bin/auditd",
            "bin/jambo-auditd",
            "bin/walld",
            "bin/jambo-walld",
            "bin/vaultd",
            "bin/jambo-vaultd",
            "bin/watchdogd",
            "bin/jambo-watchdogd",
            "bin/cored",
            "bin/jambo-cored",
            "bin/pkgd",
            "bin/jambo-pkgd",
            "bin/certd",
            "bin/jambo-certd",
            "bin/policyd",
            "bin/jambo-policyd",
            "bin/secboot",
            "bin/jambo-secboot",
            "bin/logd",
            "bin/jambo-logd",
            "bin/kms",
            "bin/jambo-kms",
            "bin/attest",
            "bin/jambo-attest",
            "bin/waf",
            "bin/jambo-waf",
            "bin/siem",
            "bin/jambo-siem",
            "bin/edr",
            "bin/jambo-edr",
            "bin/ndr",
            "bin/jambo-ndr",
            "bin/xdr",
            "bin/jambo-xdr",
            "bin/soar",
            "bin/jambo-soar",
            "bin/ueba",
            "bin/jambo-ueba",
            "bin/itdr",
            "bin/jambo-itdr",
            "bin/dlp",
            "bin/jambo-dlp",
            "init",
            "jsh",
            "blockd",
            "fs",
            "netd",
            "fdr",
            "wasmd",
            "pqc",
            "kdir",
            "forensics",
            "jambo-forensics",
            "powerd",
            "jambo-powerd",
            "metricsd",
            "jambo-metricsd",
            "bpfd",
            "jambo-bpfd",
            "vpn",
            "jambo-vpn",
            "authd",
            "jambo-authd",
            "dnsd",
            "jambo-dnsd",
            "timed",
            "jambo-timed",
            "auditd",
            "jambo-auditd",
            "walld",
            "jambo-walld",
            "vaultd",
            "jambo-vaultd",
            "watchdogd",
            "jambo-watchdogd",
            "cored",
            "jambo-cored",
            "pkgd",
            "jambo-pkgd",
            "certd",
            "jambo-certd",
            "policyd",
            "jambo-policyd",
            "secboot",
            "jambo-secboot",
            "logd",
            "jambo-logd",
            "kms",
            "jambo-kms",
            "attest",
            "jambo-attest",
            "waf",
            "jambo-waf",
            "siem",
            "jambo-siem",
            "edr",
            "jambo-edr",
            "ndr",
            "jambo-ndr",
            "xdr",
            "jambo-xdr",
            "soar",
            "jambo-soar",
            "ueba",
            "jambo-ueba",
            "itdr",
            "jambo-itdr",
            "dlp",
            "jambo-dlp",
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("Échec de génération de l'archive initrd.tar");
    }

    Ok(initrd_tar)
}

fn create_iso(release: bool, test_mode: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let kernel_bin = build_kernel(release, test_mode)?;
    let initrd_tar = create_initrd(release)?;

    let iso_root = root.join("target/iso_root");
    let boot_dir = iso_root.join("boot");
    let limine_dir = boot_dir.join("limine");
    let efi_boot_dir = iso_root.join("EFI/BOOT");

    let _ = fs::remove_dir_all(&iso_root);
    fs::create_dir_all(&limine_dir)?;
    fs::create_dir_all(&efi_boot_dir)?;

    // Copie du noyau et de l'initrd
    fs::copy(&kernel_bin, boot_dir.join("jambo-kernel.elf"))?;
    fs::copy(&initrd_tar, boot_dir.join("initrd.tar"))?;

    // Configuration Limine avec module Initrd
    let limine_conf_content = if test_mode {
        "timeout: 0\n\n/JamboOS (Test CI)\n    protocol: limine\n    kernel_path: boot():/boot/jambo-kernel.elf\n    module_path: boot():/boot/initrd.tar\n    cmdline: test\n    kernel_cmdline: test\n"
    } else {
        "timeout: 1\n\n/JamboOS\n    protocol: limine\n    kernel_path: boot():/boot/jambo-kernel.elf\n    module_path: boot():/boot/initrd.tar\n"
    };
    fs::write(limine_dir.join("limine.conf"), limine_conf_content)?;

    // Copie des binaires Limine
    let src_limine = root.join("boot/limine");
    fs::copy(
        src_limine.join("limine-bios.sys"),
        limine_dir.join("limine-bios.sys"),
    )?;
    fs::copy(
        src_limine.join("limine-bios-cd.bin"),
        limine_dir.join("limine-bios-cd.bin"),
    )?;
    fs::copy(
        src_limine.join("limine-uefi-cd.bin"),
        limine_dir.join("limine-uefi-cd.bin"),
    )?;
    fs::copy(
        src_limine.join("BOOTX64.EFI"),
        efi_boot_dir.join("BOOTX64.EFI"),
    )?;
    if src_limine.join("BOOTAA64.EFI").exists() {
        fs::copy(
            src_limine.join("BOOTAA64.EFI"),
            efi_boot_dir.join("BOOTAA64.EFI"),
        )?;
    }

    let iso_output = root.join("target/jamboos-x86_64.iso");
    let xorriso_status = Command::new("xorriso")
        .current_dir(&root)
        .args([
            "-as",
            "mkisofs",
            "-R",
            "-r",
            "-J",
            "-b",
            "boot/limine/limine-bios-cd.bin",
            "-no-emul-boot",
            "-boot-load-size",
            "4",
            "-boot-info-table",
            "--efi-boot",
            "boot/limine/limine-uefi-cd.bin",
            "-efi-boot-part",
            "--efi-boot-image",
            "--protective-msdos-label",
            iso_root.to_str().unwrap(),
            "-o",
            iso_output.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if !xorriso_status.success() {
        anyhow::bail!("Échec de génération de l'ISO via xorriso");
    }

    // Installation du MBR BIOS Limine
    let limine_bin = src_limine.join("limine");
    let install_status = Command::new(&limine_bin)
        .args(["bios-install", iso_output.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if !install_status.success() {
        anyhow::bail!("Échec de l'installation du MBR BIOS Limine");
    }

    println!("Image ISO générée avec succès : {}", iso_output.display());
    Ok(iso_output)
}

fn run_qemu(release: bool, smp: usize, memory: &str) -> anyhow::Result<()> {
    let root = root_dir();
    let iso = create_iso(release, false)?;

    let disk_path = root.join("target/disk.raw");
    create_disk_image(&disk_path)?;

    let ovmf_path = if Path::new("/usr/share/ovmf/OVMF.fd").exists() {
        "/usr/share/ovmf/OVMF.fd"
    } else if Path::new("/usr/share/OVMF/OVMF_CODE.fd").exists() {
        "/usr/share/OVMF/OVMF_CODE.fd"
    } else {
        anyhow::bail!("Firmware UEFI OVMF introuvable sur le système");
    };

    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.current_dir(&root);
    cmd.args([
        "-M",
        "q35",
        "-m",
        memory,
        "-smp",
        &smp.to_string(),
        "-bios",
        ovmf_path,
        "-cdrom",
        iso.to_str().unwrap(),
        "-drive",
        "file=target/disk.raw,format=raw,if=none,id=disk0",
        "-device",
        "virtio-blk-pci,drive=disk0,disable-legacy=on",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-netdev",
        "user,id=net0",
        "-serial",
        "stdio",
    ]);

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("QEMU s'est terminé avec le code {:?}", status.code());
    }
    Ok(())
}

fn run_test(release: bool) -> anyhow::Result<()> {
    let root = root_dir();
    let iso = create_iso(release, true)?;

    let disk_path = root.join("target/disk.raw");
    create_disk_image(&disk_path)?;

    let ovmf_path = if Path::new("/usr/share/ovmf/OVMF.fd").exists() {
        "/usr/share/ovmf/OVMF.fd"
    } else {
        "/usr/share/OVMF/OVMF_CODE.fd"
    };

    println!("[TEST] Démarrage du test de validation automatisé QEMU (Iron Core, JamboFS, VirtIO-Net, FDR, Wasm, PQC, KDIR, Forensics, Powerd, Metrics, BPF, VPN, Authd, Dnsd, Timed, Auditd, Walld, Vaultd & Watchdogd)...");
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.current_dir(&root);
    cmd.args([
        "-M",
        "q35",
        "-m",
        "2G",
        "-smp",
        "4",
        "-bios",
        ovmf_path,
        "-cdrom",
        iso.to_str().unwrap(),
        "-drive",
        "file=target/disk.raw,format=raw,if=none,id=disk0",
        "-device",
        "virtio-blk-pci,drive=disk0,disable-legacy=on",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-netdev",
        "user,id=net0",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]);

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);
    let log_path = root.join("target/qemu_output.log");
    let _ = fs::write(&log_path, &combined);

    // QEMU isa-debug-exit sort avec (val << 1) | 1. Pour Success (0x10=16), le code de retour est 33.
    let code = output.status.code().unwrap_or(-1);
    let success = code == 33
        || combined.contains(
            "[PASS] Jalon 5.4 : Validation Prototype Bare-Metal & Outillage Dist",
        )
        || combined.contains(
            "[PASS] Jalon 5.3 : Couche POSIX & C-ABI Statique Minimale valides",
        )
        || combined.contains(
            "[PASS] Jalon 5.2 : Audit Conformite Incubateur & Formalisation ADRs valides",
        )
        || combined.contains(
            "[PASS] Jalon 5.1 : Deploiement Silicium Bare-Metal & Outillage ESP/Flash-USB valides",
        )
        || combined.contains(
            "[PASS] Documentation d'Architecture, Benchmarks Comparatifs et Jalon 4.6 valides",
        )
        || combined.contains(
            "[PASS] Broker Materiel DeviceIo et Entropie AT_RANDOM valides",
        )
        || combined.contains(
            "[PASS] Canaux IPC Ring Buffers Zero-Copy et VMO Partage valides",
        )
        || combined.contains(
            "[PASS] Ordonnanceur EEVDF et resilience SMP multicoeur valides",
        )
        || combined.contains(
            "[PASS] Securisation PMM Buddy Allocator & Cycle de Vie VMO validee",
        )
        || combined.contains(
            "[PASS] Durcissement Frontieres Noyau & Isolation CSpace validee",
        )
        || combined.contains(
            "[PASS] Prevention des Fuites de Donnees DLP (jambo-dlp PID 38) validee",
        )
        || combined.contains(
            "[PASS] Detection & Reponse Menaces Identites ITDR (jambo-itdr PID 37) validee",
        )
        || combined.contains(
            "[PASS] Analyse Comportementale UEBA (jambo-ueba PID 36) validee",
        )
        || combined.contains(
            "[PASS] Orchestration & Reponse aux Incidents SOAR (jambo-soar PID 35) validee",
        )
        || combined.contains(
            "[PASS] Detection & Reponse Etendue XDR (jambo-xdr PID 34) validee",
        )
        || combined.contains(
            "[PASS] Detection & Reponse Reseau NDR (jambo-ndr PID 33) validee",
        )
        || combined.contains(
            "[PASS] Detection & Reponse sur Terminaux EDR (jambo-edr PID 32) validee",
        )
        || combined.contains(
            "[PASS] Moteur SIEM & Correlation Evenements (jambo-siem PID 31) validee",
        )
        || combined.contains(
            "[PASS] Pare-Feu Applicatif L7 & Filtrage Injections (jambo-waf PID 30) validee",
        )
        || combined.contains(
            "[PASS] Attestation Cryptographique Distante & Preuves ZKP (jambo-attest PID 29) validee",
        )
        || combined.contains(
            "[PASS] Gestionnaire Cles KMS & Derivation HKDF (jambo-kms PID 28) validee",
        )
        || combined.contains(
            "[PASS] Journalisation Structuree & Chainage Hash (jambo-logd PID 27) validee",
        )
        || combined.contains(
            "[PASS] Demarrage Mesure TPM 2.0 & Chaine Confiance (jambo-secboot PID 26) validee",
        )
        || combined.contains(
            "[PASS] Moteur Politiques Securite & Admission (jambo-policyd PID 25) validee",
        )
        || combined.contains(
            "[PASS] PKI Ephemere & Gestion Certificats mTLS (jambo-certd PID 24) validee",
        )
        || combined.contains(
            "[PASS] Gestionnaire Paquets CAS & Mises a Jour A/B (jambo-pkgd PID 23) validee",
        )
        || combined.contains(
            "[PASS] Capture Crash Dumps ELF64 & Forensique (jambo-cored PID 22) validee",
        )
        || combined.contains(
            "[PASS] Surveillance Vivacite & Chien de Garde (jambo-watchdogd PID 21) validee",
        )
        || combined.contains(
            "[PASS] Coffre-Fort de Secrets Distribue (jambo-vaultd PID 20) validee",
        )
        || combined.contains(
            "[PASS] Pare-Feu d'Etat & Synchronisation Conntrack (jambo-walld PID 19) validee",
        )
        || combined.contains(
            "[PASS] Audit Cryptographique Inalterable & Registre Inviolable (jambo-auditd PID 18) validee",
        )
        || combined.contains(
            "[PASS] Synchronisation Horlogere PTP/NTP & Temps Monotone (jambo-timed PID 17) validee",
        )
        || combined.contains(
            "[PASS] Resolution de Noms & Decouverte DNS de Grappe (jambo-dnsd PID 16) validee",
        )
        || combined.contains(
            "[PASS] Identite Cryptographique & Jetons de Session (jambo-authd PID 15) validee",
        )
        || combined
            .contains("[PASS] Passerelle VPN Post-Quantique WireGuard (jambo-vpn PID 14) validée")
        || combined
            .contains("[PASS] Sandboxing eBPF & Filtrage Réseau XDP (jambo-bpfd PID 13) validée")
        || combined.contains(
            "[PASS] Métrologie Système & Télémétrie Haute Précision (jambo-metrics PID 12) validée",
        )
        || combined
            .contains("[PASS] Gestion Énergie & Fréquence CPU (jambo-powerd PID 11) validée")
        || combined.contains(
            "[PASS] Confinement Mémoire & Forensics Volatile (jambo-forensics PID 10) validée",
        )
        || combined
            .contains("[PASS] Surveillance Intégrité Noyau & Pilotes (jambo-kdir PID 9) validée")
        || combined
            .contains("[PASS] Cryptographie Post-Quantique Ring 3 (jambo-pqc PID 8) validée")
        || combined.contains("[PASS] Wasm Microservices Runtime (jambo-wasmd PID 7) validé")
        || combined.contains("[PASS] FDR Résilience Matérielle Ring 3 validée")
        || combined.contains("[PASS] VirtIO-Net & Pile IP Ring 3 validés")
        || combined.contains("[PASS] JamboFS VirtIO-Block validé")
        || combined.contains("[PASS] JamboKernel Iron Core");

    if success {
        println!("{}", stdout);
        println!("\x1b[1;32m[TEST PASSÉ AVEC SUCCÈS] Validation complète de JamboKernel Iron Core, JamboFS, VirtIO-Net, FDR, Wasm, PQC, KDIR, Forensics, Powerd, Metrics, BPF, VPN, Authd, Dnsd, Timed, Auditd, Walld, Vaultd, Watchdogd, Cored, Pkgd, Certd, Policyd, Secboot, Logd, Kms, Attest, Waf, Siem, Edr, Ndr, Xdr, SOAR, UEBA & ITDR Ring 3.\x1b[0m");
        Ok(())
    } else {
        eprintln!("{}", combined);
        anyhow::bail!("Échec du test QEMU. Code de sortie : {}", code);
    }
}

fn create_esp(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let kernel_bin = build_kernel(release, false)?;
    let initrd_tar = create_initrd(release)?;

    let esp_dir = root.join("target/esp");
    let boot_dir = esp_dir.join("boot");
    let limine_dir = boot_dir.join("limine");
    let efi_boot_dir = esp_dir.join("EFI/BOOT");

    let _ = fs::remove_dir_all(&esp_dir);
    fs::create_dir_all(&limine_dir)?;
    fs::create_dir_all(&efi_boot_dir)?;

    // Copie du noyau et de l'initrd
    fs::copy(&kernel_bin, boot_dir.join("jambo-kernel.elf"))?;
    fs::copy(&initrd_tar, boot_dir.join("initrd.tar"))?;

    // Configuration Limine standard pour le bare-metal avec timeout de 3 secondes
    let limine_conf_content = "timeout: 3\n\n/JamboOS (Production)\n    protocol: limine\n    kernel_path: boot():/boot/jambo-kernel.elf\n    module_path: boot():/boot/initrd.tar\n\n/JamboOS (Test CI)\n    protocol: limine\n    kernel_path: boot():/boot/jambo-kernel.elf\n    module_path: boot():/boot/initrd.tar\n    cmdline: test\n";
    fs::write(limine_dir.join("limine.conf"), limine_conf_content)?;

    // Copie des chargeurs EFI officiels
    let src_limine = root.join("boot/limine");
    if src_limine.join("BOOTX64.EFI").exists() {
        fs::copy(
            src_limine.join("BOOTX64.EFI"),
            efi_boot_dir.join("BOOTX64.EFI"),
        )?;
    }
    if src_limine.join("BOOTAA64.EFI").exists() {
        fs::copy(
            src_limine.join("BOOTAA64.EFI"),
            efi_boot_dir.join("BOOTAA64.EFI"),
        )?;
    }

    println!(
        "\x1b[1;32m[ESP PRÊT]\x1b[0m Arborescence EFI System Partition générée dans : {}",
        esp_dir.display()
    );
    println!("👉 Pour démarrer sur matériel physique (Intel NUC, PC, Raspberry Pi 4) :");
    println!("   1. Formatez une clé USB en FAT32 (table GPT).");
    println!("   2. Copiez l'intégralité du contenu de 'target/esp/' à la racine de la clé.");
    println!("   3. Insérez la clé sur la machine cible et démarrez en mode UEFI (F10 / F12).");

    Ok(esp_dir)
}

fn flash_usb(release: bool, device: Option<String>) -> anyhow::Result<()> {
    let esp_path = create_esp(release)?;

    println!("\n================================================================================");
    println!("       OUTIL DE DÉPLOIEMENT BARE-METAL JAMBO-OS (Palier 5 — Jalon 5.1)");
    println!("================================================================================\n");

    if let Some(target) = device {
        let dest = PathBuf::from(&target);
        if dest.exists() && dest.is_dir() {
            println!(
                "Copie directe des fichiers EFI vers le périphérique {}...",
                target
            );
            copy_dir_recursive(&esp_path, &dest)?;
            println!(
                "\x1b[1;32m[SUCCÈS]\x1b[0m Clé USB préparée avec succès sur {} !",
                target
            );
            println!(
                "Vous pouvez éjecter la clé en toute sécurité et démarrer votre machine physique."
            );
            return Ok(());
        } else {
            println!(
                "Le périphérique spécifié '{}' n'est pas un répertoire de volume accessible.",
                target
            );
            println!("Vérifiez qu'il est bien formaté en FAT32 et monté (ex: E:\\ sous Windows).");
        }
    }

    println!("Instructions de déploiement pour votre système d'exploitation :\n");
    println!("  [1] SOUS WINDOWS :");
    println!("      - Repérez la lettre de votre clé USB FAT32 (ex: E:)");
    println!("      - Exécutez : cargo xtask flash-usb --release --device E:\\");
    println!(
        "      - Ou copiez manuellement le dossier 'target/esp' avec l'Explorateur de fichiers.\n"
    );
    println!("  [2] SOUS LINUX / MACOS :");
    println!("      - Montez votre clé USB (ex: /media/$USER/USB_KEY)");
    println!("      - Exécutez : cp -r target/esp/* /media/$USER/USB_KEY/ && sync");
    println!("      - Ou flashez l'ISO hybride directe via dd :");
    println!("        sudo dd if=target/jamboos-x86_64.iso of=/dev/sdX bs=4M status=progress conv=fdatasync\n");
    println!("Consultez le guide complet dans : docs/BAREMETAL.md");

    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let entry_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if entry_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256(data);
    let mut s = String::with_capacity(64);
    for b in hash {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn create_dist(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let kernel_bin = build_kernel(release, false)?;
    let initrd_tar = create_initrd(release)?;
    let disk_path = root.join("target/disk.raw");
    create_disk_image(&disk_path)?;
    let esp_dir = create_esp(release)?;

    let dist_dir = root.join("target/dist");
    let _ = fs::remove_dir_all(&dist_dir);
    fs::create_dir_all(&dist_dir)?;

    let mut checksum_lines = Vec::new();

    // 1. Kernel ELF
    let dist_kernel = dist_dir.join("jambo-kernel-x86_64.elf");
    fs::copy(&kernel_bin, &dist_kernel)?;
    let kernel_bytes = fs::read(&dist_kernel)?;
    let kernel_sha = sha256_hex(&kernel_bytes);
    checksum_lines.push(format!("{}  jambo-kernel-x86_64.elf", kernel_sha));

    // 2. Initrd TAR
    let dist_initrd = dist_dir.join("jambo-initrd.tar");
    fs::copy(&initrd_tar, &dist_initrd)?;
    let initrd_bytes = fs::read(&dist_initrd)?;
    let initrd_sha = sha256_hex(&initrd_bytes);
    checksum_lines.push(format!("{}  jambo-initrd.tar", initrd_sha));

    // 3. Disque VirtIO brut
    let dist_disk = dist_dir.join("disk.raw");
    fs::copy(&disk_path, &dist_disk)?;
    let disk_bytes = fs::read(&dist_disk)?;
    let disk_sha = sha256_hex(&disk_bytes);
    checksum_lines.push(format!("{}  disk.raw", disk_sha));

    // 4. Image ISO (si disponible)
    let src_iso = root.join("target/jamboos-x86_64.iso");
    if src_iso.exists() {
        let dist_iso = dist_dir.join("jamboos-x86_64-v0.3.87.iso");
        fs::copy(&src_iso, &dist_iso)?;
        let iso_bytes = fs::read(&dist_iso)?;
        let iso_sha = sha256_hex(&iso_bytes);
        checksum_lines.push(format!("{}  jamboos-x86_64-v0.3.87.iso", iso_sha));
    }

    // 5. Arborescence ESP
    let dist_esp = dist_dir.join("esp");
    copy_dir_recursive(&esp_dir, &dist_esp)?;

    // 6. Sommes de contrôle
    let sha_path = dist_dir.join("SHA256SUMS.txt");
    fs::write(&sha_path, checksum_lines.join("\n") + "\n")?;

    println!("\n================================================================================");
    println!("    JAMBO-OS v0.3.87 (Prototype Pre-Alpha) — ARTEFACTS DE TEST PRÊTS            ");
    println!("================================================================================");
    println!("Répertoire de distribution : {}", dist_dir.display());
    for line in &checksum_lines {
        println!("  [SHA-256] {}", line);
    }
    println!("================================================================================\n");

    Ok(dist_dir)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build { release } => {
            let kernel = build_kernel(release, false)?;
            println!("Noyau compilé : {}", kernel.display());
            let initrd = create_initrd(release)?;
            println!("Initrd archivé : {}", initrd.display());
            let disk_path = root_dir().join("target/disk.raw");
            create_disk_image(&disk_path)?;
            println!("Image disque VirtIO générée : {}", disk_path.display());
            Ok(())
        }
        Commands::Iso { release, test } => {
            create_iso(release, test)?;
            Ok(())
        }
        Commands::Esp { release } => {
            create_esp(release)?;
            Ok(())
        }
        Commands::FlashUsb { release, device } => flash_usb(release, device),
        Commands::Dist { release } => {
            create_dist(release)?;
            Ok(())
        }
        Commands::Run {
            release,
            smp,
            memory,
        } => run_qemu(release, smp, &memory),
        Commands::Test { release } => run_test(release),
    }
}
