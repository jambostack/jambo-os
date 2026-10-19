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
    /// Lance l'image ISO sous QEMU en mode graphique avec console série
    Qemu {
        #[arg(long)]
        release: bool,
        #[arg(long, default_value = "4")]
        smp: usize,
        #[arg(long, default_value = "2G")]
        memory: String,
    },
    /// Exécute les tests automatisés de démarrage sous QEMU pour la CI
    Test {
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

fn create_initrd(release: bool) -> anyhow::Result<PathBuf> {
    let root = root_dir();
    let init_bin = build_init(release)?;
    let jsh_bin = build_jsh(release)?;

    let initrd_stage = root.join("target/initrd_stage");
    let bin_dir = initrd_stage.join("bin");
    let _ = fs::remove_dir_all(&initrd_stage);
    fs::create_dir_all(&bin_dir)?;

    fs::copy(&init_bin, bin_dir.join("init"))?;
    fs::copy(&jsh_bin, bin_dir.join("jsh"))?;

    let initrd_tar = root.join("target/initrd.tar");
    let status = Command::new("tar")
        .current_dir(&initrd_stage)
        .args(["-cf", initrd_tar.to_str().unwrap(), "bin/init", "bin/jsh"])
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
        "timeout: 0\n\n/JamboOS (Test CI)\n    protocol: limine\n    kernel_path: boot():/boot/jambo-kernel.elf\n    module_path: boot():/boot/initrd.tar\n    cmdline: test\n"
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

    let ovmf_path = if Path::new("/usr/share/ovmf/OVMF.fd").exists() {
        "/usr/share/ovmf/OVMF.fd"
    } else {
        "/usr/share/OVMF/OVMF_CODE.fd"
    };

    println!("[TEST] Démarrage du test de validation automatisé QEMU (Phase 2)...");
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

    // QEMU isa-debug-exit sort avec (val << 1) | 1. Pour Success (0x10=16), le code de retour est 33.
    let code = output.status.code().unwrap_or(-1);
    let success = code == 33 || combined.contains("[PASS] Phase 2 Bootstrap Complete");

    if success {
        println!("{}", stdout);
        println!("\x1b[1;32m[TEST PASSÉ AVEC SUCCÈS] Validation complète de la Phase 2.\x1b[0m");
        Ok(())
    } else {
        eprintln!("{}", combined);
        anyhow::bail!("Échec du test QEMU. Code de sortie : {}", code);
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build { release } => {
            let path = build_kernel(release, false)?;
            println!("Noyau compilé : {}", path.display());
            Ok(())
        }
        Commands::Iso { release, test } => {
            create_iso(release, test)?;
            Ok(())
        }
        Commands::Qemu {
            release,
            smp,
            memory,
        } => run_qemu(release, smp, &memory),
        Commands::Test { release } => run_test(release),
    }
}
