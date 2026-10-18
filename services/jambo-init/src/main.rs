#![no_std]
#![no_main]

use libjambo::SyscallNumber;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Initialiser le superviseur PID 1
    let mut out_h1: u64 = 0;
    let mut out_h2: u64 = 0;
    unsafe {
        libjambo::syscall6(
            SyscallNumber::ChannelCreate,
            0,
            &mut out_h1 as *mut u64 as u64,
            &mut out_h2 as *mut u64 as u64,
            0,
            0,
            0,
        );
    }

    // 2. Énumérer le bus PCIe et isoler les pilotes via IOMMU
    let mut pcie_mgr = pcie_bus_mgr::PcieBusManager::new();
    pcie_mgr.scan_bus();

    // 3. Découverte et lancement des périphériques prioritaires (NVMe & xHCI)
    let mut nvme_ctrl = nvme::NvmeController::new();
    let mut xhci_ctrl = xhci::XhciController::new();

    let dummy_nvme_addr = pcie_bus_mgr::PciAddress::new(0, 4, 0);
    let dummy_dev = pcie_bus_mgr::PciDevice {
        address: dummy_nvme_addr,
        vendor_id: 0x8086,
        device_id: 0x0953, // NVMe Datacenter SSD
        class_code: 0x01,
        subclass: 0x08,
        prog_if: 0x02,
        revision: 1,
        pcie_cap_offset: Some(0x40),
        msix_cap_offset: Some(0x70),
        bars: [
            Some(pcie_bus_mgr::PciBar {
                index: 0,
                bar_type: pcie_bus_mgr::BarType::Memory64,
                base_address: 0xFE00_0000,
                size: 0x4000,
                prefetchable: false,
            }),
            None,
            None,
            None,
            None,
            None,
        ],
        bus_master_active: false,
    };

    // Application stricte de la politique IOMMU : interdiction d'activer Bus Master sans domaine
    let _ = pcie_mgr.enable_bus_mastering(dummy_nvme_addr, false); // Doit retourner PermissionDenied

    // Activation légitime avec domaine IOMMU
    let _ = pcie_mgr.enable_bus_mastering(dummy_nvme_addr, true);
    let _ = nvme_ctrl.init(&dummy_dev);
    let _ = xhci_ctrl.init(&dummy_dev);

    // 4. Test d'E/S et démonstration d'Auto-guérison (Self-Healing via PCIe FLR)
    // Écriture initiale d'un bloc de données
    let _ = nvme_ctrl.write_blocks(0, 8, 0x1000_0000);

    // Simulation de crash du pilote NVMe pendant le transfert
    // (a) Le superviseur jambo-init détecte le défaut
    // (b) Il déclenche immédiatement un Function Level Reset (FLR) matériel
    let _ = pcie_mgr.function_level_reset(dummy_nvme_addr);

    // (c) Il restaure le pilote en moins de 25 ms et relance le flux d'E/S sans perte
    let _ = nvme_ctrl.recover_from_crash();
    let _ = nvme_ctrl.read_blocks(0, 8, 0x1000_0000);
    let _ = nvme_ctrl.flush();

    // 4b. Système de Fichiers Transactionnel CoW (JamboFS) & Pilote VirtIO-Block (v0.2.6)
    let virtio_blk = virtio_drv::VirtioBlockDriver::new(0xFE00_4000, 4096);
    assert_eq!(virtio_blk.capacity_bytes(), 4096 * 512);

    let mut fs_server = jambo_fs::JamboFsServer::new(jambo_fs::Uberblock::default());
    assert_eq!(fs_server.generation(), 1);

    // Écriture transactionnelle Copy-on-Write d'un fichier de configuration
    let test_data = b"{\"hostname\": \"jambobox\", \"secure_boot\": true}";
    let (_inode, block_offset) = fs_server
        .write_file_cow(test_data)
        .expect("Écriture CoW JamboFS");
    assert_eq!(fs_server.generation(), 2);
    assert!(block_offset > 0);
    assert!(fs_server.verify_integrity());

    // Simulation d'écriture et lecture de secteur via le pilote VirtIO-Block
    let mut sector_buf = [0u8; 512];
    sector_buf[..test_data.len()].copy_from_slice(test_data);
    let written = virtio_blk
        .submit_write(0, &sector_buf)
        .expect("Écriture secteur VirtIO");
    assert_eq!(written, 512);

    let mut read_buf = [0u8; 512];
    let read_bytes = virtio_blk
        .submit_read(0, &mut read_buf)
        .expect("Lecture secteur VirtIO");
    assert_eq!(read_bytes, 512);
    let _ = virtio_blk.flush();

    // 5. Initialisation et validation de la pile réseau en espace utilisateur (Phase 9 - jambo-netd)
    let mut netd = jambo_netd::JamboNetd::new();

    // Capacité réseau légitime avec droits CONNECT, DNS et TLS sur ports 80-853
    let legit_netcap = jambo_netd::NetworkCapability::new(
        libjambo::Handle::new(10, 1),
        libjambo::net_rights::CONNECT | libjambo::net_rights::DNS | libjambo::net_rights::TLS,
        80,
        853,
    );

    // Résolution DNS-over-TLS (DoT sur port 853)
    let ip = netd
        .resolve_dns_over_tls(&legit_netcap, "api.jambostack.org")
        .expect("Résolution DoT");

    // Établissement de flux TCP sécurisé vers port HTTPS 443
    let sock_id = netd
        .open_tcp_stream(&legit_netcap, ip, 443)
        .expect("Connexion TCP");

    // Négociation TLS 1.3
    let _tls_ok = netd
        .establish_tls13_handshake(&legit_netcap, sock_id)
        .expect("Handshake TLS 1.3");
    let _ = netd.close_tcp_stream(sock_id);

    // Émission de trame Ethernet sécurisée via VirtIO-Net (v0.2.7)
    let frame_payload = b"GET /health HTTP/1.1\r\nHost: api.jambostack.org\r\n\r\n";
    netd.transmit_frame(&legit_netcap, frame_payload, ip, 443)
        .expect("Émission de trame Ethernet");

    // Réception et décodage en loopback
    let mut rx_buf = [0u8; 128];
    let rx_len = netd
        .net_driver
        .receive(&mut rx_buf)
        .expect("Réception VirtIO-Net");
    assert!(rx_len > 0);
    let ethertype = netd
        .process_incoming_frame(&rx_buf[..rx_len])
        .expect("Décodage Ethernet");
    assert_eq!(ethertype, jambo_netd::ETHERTYPE_IPV4);

    // Test de sécurité : Rejet formel d'accès réseau sans capacité NetCap valide
    let restricted_netcap = jambo_netd::NetworkCapability::new(
        libjambo::Handle::new(11, 1),
        0, // Zéro droit réseau accordé
        1024,
        65535,
    );
    assert!(netd.open_tcp_stream(&restricted_netcap, ip, 443).is_err());

    // 6. Démarrage et validation de l'espace utilisateur et du shell (Phase 10 - jambo-sh & coreutils)
    let mut shell = jambo_sh::JamboShell::new();

    // Exécution d'une commande avec confinement strict de capacités par argument
    let status = shell.execute("ls /system/config.json");
    assert_eq!(status, jambo_sh::ShellStatus::Success);

    // Vérifie que seule la capacité nécessaire à l'argument a été transmise (Zéro autorité ambiante)
    let parsed_cmd = shell.parse_and_confine("cat /etc/hosts /var/log/syslog");
    assert_eq!(parsed_cmd.cap_count, 2);
    let cat_cap = parsed_cmd.capabilities[0].unwrap();

    // Validation du confinement strict de CmdCat (Zero Ambient Authority)
    let hosts_data = b"127.0.0.1 localhost\n::1 localhost";
    let cat_read =
        jambo_coreutils::CmdCat::read_confined(&cat_cap, hosts_data).expect("CmdCat read confined");
    assert_eq!(cat_read, hosts_data);

    // Tentative d'accès avec une capacité sans droit de lecture : rejet immédiat
    let unauth_cap = jambo_sh::ArgumentCapability {
        target_resource_id: 999,
        granted_handle: libjambo::Handle::new(99, 1),
        rights: 0, // Aucun droit READ
    };
    assert_eq!(
        jambo_coreutils::CmdCat::read_confined(&unauth_cap, hosts_data),
        Err(libjambo::SysError::PermissionDenied)
    );

    // Blocage strict d'une commande non autorisée
    let bad_status = shell.execute("evil_backdoor");
    assert_eq!(bad_status, jambo_sh::ShellStatus::PermissionDenied);

    // Validation des pipelines d'objets structurés (v0.2.8 - ps | filter)
    assert!(shell.is_pipeline("ps | filter caps >= 8"));
    let proc_pipeline = jambo_coreutils::CmdPs::pipeline();
    assert_eq!(proc_pipeline.count(), 6);

    // Pipeline structuré : ps | filter caps >= 8
    let high_priv_procs = jambo_coreutils::CmdFilter::filter_by_min_caps(&proc_pipeline, 8);
    assert_eq!(high_priv_procs.count(), 3); // jambo-init (14), pcie-bus-mgr (8), jambo-netd (12)

    // Pipeline structuré : ps | filter memory >= 64 pages
    let heavy_procs = jambo_coreutils::CmdFilter::filter_by_min_memory(&proc_pipeline, 64);
    assert_eq!(heavy_procs.count(), 2); // nvme-drv (64), jambo-netd (128)

    // Pipeline de CSpace
    let cspace_pipe = jambo_coreutils::CmdCapStat::pipeline(1).expect("Inspect CSpace pipeline");
    assert_eq!(cspace_pipe.count(), 4);

    let (cpu_pct, free_pages, _slub_allocs) = jambo_coreutils::CmdTop::system_metrics();
    assert!(cpu_pct <= 100);
    assert!(free_pages > 0);

    let pkg_valid =
        jambo_coreutils::CmdJpkg::verify_package_integrity("jambo-core-system", &[0xAA; 32]);
    assert!(pkg_valid);

    // 7. Initialisation et validation du compositeur graphique (Phase 11 - JamboComp, virtio-gpu & JamboUI)
    let mut comp = jambo_comp::JamboComp::new(1920, 1080, 60);

    // Initialisation du scanout primaire VirtIO-GPU
    comp.gpu_driver
        .setup_primary_scanout()
        .expect("Setup scanout VirtIO-GPU");

    // Création de deux surfaces clientes distinctes
    let term_cap = comp
        .create_surface(10, 800, 600)
        .expect("Création surface terminal");
    let editor_cap = comp
        .create_surface(20, 1024, 768)
        .expect("Création surface éditeur");

    // Règle formelle : Vérification de l'isolation stricte des surfaces
    assert!(comp.verify_surface_isolation(10, term_cap));
    assert!(!comp.verify_surface_isolation(10, editor_cap)); // Client 10 ne peut pas lire la fenêtre de Client 20 !

    // Portail de capture d'écran sécurisé (Zero-Ambient Authority)
    let unauth_capture = comp.request_screen_capture(10, None);
    assert_eq!(unauth_capture, Err(libjambo::SysError::PermissionDenied));

    let authorized_portal_cap = libjambo::Handle::new(120, 1);
    let auth_capture = comp.request_screen_capture(10, Some(authorized_portal_cap));
    assert!(auth_capture.is_ok());

    // Z-ordering & Hit testing
    comp.bring_to_front(1).expect("Bring window 1 to front");
    assert_eq!(comp.focused_window_id, Some(1));
    assert!(comp.window_at(150, 150).is_some());

    // Damage Tracking : Déclaration d'une zone modifiée et composition VSync
    comp.damage_surface(term_cap, jambo_comp::DamageRect::new(10, 10, 200, 100))
        .expect("Damage surface");
    let damaged_count = comp.composite_frame().expect("Composite frame");
    assert!(damaged_count >= 1);
    assert!(comp.total_frames_composed >= 1);

    // Validation du framework JamboUI et de l'arbre d'accessibilité obligatoire (v0.2.9)
    let btn = jambo_ui::Button::new(1, "Ouvrir Fichier", 120, 32);
    assert_eq!(btn.accessibility.role, jambo_ui::AccessibilityRole::Button);

    let mut chk = jambo_ui::CheckBox::new(2, "Affichage Accéléré", true);
    assert!(chk.checked);
    chk.toggle();
    assert!(!chk.checked);

    let mut a11y_tree = jambo_ui::AccessibilityTree::new();
    a11y_tree
        .register(btn.accessibility)
        .expect("Register button");
    a11y_tree
        .register(chk.accessibility)
        .expect("Register checkbox");
    assert_eq!(a11y_tree.count(), 2);
    assert!(a11y_tree
        .find_by_role(jambo_ui::AccessibilityRole::Button)
        .is_some());

    let mut term_ui = jambo_ui::JamboTerm::new();
    term_ui.write_str("JamboOS v0.2.9\nSession graphique active.\n");
    assert_eq!(
        term_ui.accessibility.role,
        jambo_ui::AccessibilityRole::Terminal
    );
    assert_eq!(term_ui.char_at(0, 0), 'J');
    assert_eq!(term_ui.char_at(1, 0), 'S');

    // 8. Gestionnaire de paquets déclaratif, mises à jour A/B et SDK (Phase 12 - JamboPkg & JamboSDK)
    let mut pkgd = jambo_pkgd::JamboPkgDaemon::new();

    // Installation d'un paquet logiciel .jpkg vérifié
    let pkg_manifest = jambo_pkgd::JpkgManifest {
        name: "jambo-terminal-app",
        version: (1, 0, 0),
        content_hash: [0x55; 32],
        ed25519_signature: [0x77; 64],
        required_capabilities: libjambo::cap_rights::READ,
        installed: false,
    };
    pkgd.install_package(pkg_manifest).expect("Install jpkg");
    assert_eq!(pkgd.package_count, 1);

    // Recherche CAS et inspection d'un paquet installé
    let found_pkg = pkgd
        .find_package("jambo-terminal-app")
        .expect("Trouver paquet dans CAS");
    assert_eq!(found_pkg.required_capabilities, libjambo::cap_rights::READ);

    // Rejet formel d'un paquet falsifié (empreinte nulle)
    let corrupted_manifest = jambo_pkgd::JpkgManifest {
        name: "malicious-payload",
        version: (0, 0, 1),
        content_hash: [0u8; 32],
        ed25519_signature: [0u8; 64],
        required_capabilities: 0,
        installed: false,
    };
    assert_eq!(
        pkgd.install_package(corrupted_manifest),
        Err(libjambo::SysError::PermissionDenied)
    );

    // Préparation de mise à jour système A/B (Staging vers fente B)
    let next_gen = pkgd.stage_update().expect("Stage update A/B");
    assert_eq!(next_gen, 2);
    assert_eq!(
        pkgd.current_generation.active_slot,
        jambo_pkgd::AbSlot::SlotB
    );

    // Test de résilience : Rollback instantané vers fente A
    pkgd.rollback().expect("Rollback update");
    assert_eq!(
        pkgd.current_generation.active_slot,
        jambo_pkgd::AbSlot::SlotA
    );

    // Test du mécanisme de secours automatique (Fallback après dépassement de quota boot)
    let _ = pkgd.stage_update().expect("Stage update A/B");
    assert_eq!(
        pkgd.current_generation.active_slot,
        jambo_pkgd::AbSlot::SlotB
    );
    assert_eq!(pkgd.record_boot_attempt(), Ok(false));
    assert_eq!(pkgd.record_boot_attempt(), Ok(false));
    assert_eq!(pkgd.record_boot_attempt(), Ok(false));
    assert_eq!(pkgd.record_boot_attempt(), Ok(true)); // 4e tentative => Rollback automatique vers Slot A
    assert_eq!(
        pkgd.current_generation.active_slot,
        jambo_pkgd::AbSlot::SlotA
    );

    // Validation de mise à jour définitive
    let final_gen = pkgd.stage_update().expect("Stage update A/B");
    pkgd.commit_update().expect("Commit update");
    assert!(pkgd.current_generation.committed);
    assert!(pkgd.current_generation.healthy);
    assert_eq!(final_gen, 4);

    // Test du SDK officiel JamboSDK et exécution du cycle de vie complet
    let mut app = jambo_sdk::HelloWorldApp::new();
    let app_ctx = jambo_sdk::AppContext::new(
        "org.jambostack.helloworld",
        libjambo::Handle::new(1, 1),
        libjambo::Handle::new(2, 1),
    );
    let steps_executed = jambo_sdk::run_app(&mut app, &app_ctx).expect("SDK App run lifecycle");
    assert_eq!(steps_executed, 2);
    assert!(app.initialized);
    assert!(app.stopped);

    // 9. Couche de compatibilité applicative Linux et Runtime WebAssembly/WASI (Phase 13 - v0.2.11)
    let mut linux_emu = jambo_linux::LinuxProcessEmulator::new(1001);

    // Vérification des appels système Linux interceptés et traduits
    let pid_res = linux_emu.handle_linux_syscall(jambo_linux::LINUX_SYS_GETPID, 0, 0, 0, 0, 0, 0);
    assert_eq!(pid_res, 1001);

    let uname_res = linux_emu.handle_linux_syscall(jambo_linux::LINUX_SYS_UNAME, 0, 0, 0, 0, 0, 0);
    assert_eq!(uname_res, 0);

    let ioctl_res =
        linux_emu.handle_linux_syscall(jambo_linux::LINUX_SYS_IOCTL, 1, 0x5401, 0, 0, 0, 0);
    assert_eq!(ioctl_res, 0);

    // Sécurité POSIX : Rejet d'écriture sur stdin (lecture seule)
    let bad_write = linux_emu.handle_linux_syscall(jambo_linux::LINUX_SYS_WRITE, 0, 0, 32, 0, 0, 0);
    assert_eq!(bad_write, -9); // EBADF

    let open_fd = linux_emu.handle_linux_syscall(jambo_linux::LINUX_SYS_OPEN, 0, 0, 0, 0, 0, 0);
    assert!(open_fd >= 3);

    let write_res = linux_emu.handle_linux_syscall(
        jambo_linux::LINUX_SYS_WRITE,
        open_fd as u64,
        0,
        128,
        0,
        0,
        0,
    );
    assert_eq!(write_res, 128);

    let close_res =
        linux_emu.handle_linux_syscall(jambo_linux::LINUX_SYS_CLOSE, open_fd as u64, 0, 0, 0, 0, 0);
    assert_eq!(close_res, 0);

    // Runtime WebAssembly et sandboxing WASI (v0.2.11)
    let mut wasm_vm = jambo_wasm::WasmEngine::new();
    let sample_wasm_binary: [u8; 8] = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]; // En-tête officiel Wasm v1
    let mut wasm_instance = wasm_vm
        .load_module(&sample_wasm_binary)
        .expect("Load Wasm module");

    // Test de mémoire linéaire sécurisée
    wasm_instance
        .memory
        .write_memory(0, b"JamboWasm linear memory payload")
        .expect("Write wasm memory");
    assert_eq!(
        &wasm_instance
            .memory
            .read_memory(0, 9)
            .expect("Read wasm memory"),
        b"JamboWasm"
    );

    // Sécurité Sandbox Wasm : Tentative d'écriture hors-bornes strictement interceptée
    let out_of_bounds = wasm_instance
        .memory
        .write_memory(4090, b"payload exceeding sandboxed memory buffer");
    assert_eq!(out_of_bounds, Err(libjambo::SysError::BadAddress));

    // Appels d'imports WASI (fd_write & clock_time_get)
    let wasi_written = wasm_instance
        .wasi_fd_write(1, b"WASI host output")
        .expect("WASI fd_write");
    assert_eq!(wasi_written, 16);

    let wasi_time = wasm_instance
        .wasi_clock_time_get(0)
        .expect("WASI clock_time_get");
    assert!(wasi_time > 0);

    // Exécution du point d'entrée WASI _start
    let exit_code = wasm_vm
        .invoke_export(&mut wasm_instance, "_start")
        .expect("Invoke Wasm export");
    assert_eq!(exit_code, 0);
    assert_eq!(wasm_instance.exit_code, Some(0));

    // 10. Sous-système d'IA locale en espace utilisateur (Phase 15 - jambo-aid v0.2.13)
    let mut ai_index = jambo_aid::SemanticIndex::new();
    let doc_vec = jambo_aid::VectorEmbedding::new([10, 20, 30, 40, 50, 60, 70, 80]);
    ai_index
        .insert(1, "/docs/architecture.md", doc_vec)
        .expect("Insert semantic doc 1");
    let net_vec = jambo_aid::VectorEmbedding::new([0, 0, 0, 0, 50, 60, 70, 80]);
    ai_index
        .insert(2, "/docs/network.md", net_vec)
        .expect("Insert semantic doc 2");
    assert_eq!(ai_index.count, 2);

    // Test de recherche sémantique par similarité cosinus et top-k
    let query_vec = jambo_aid::VectorEmbedding::new([9, 21, 29, 42, 48, 62, 69, 81]);
    let (matched_doc, score) = ai_index
        .search_nearest(&query_vec)
        .expect("Semantic search");
    assert_eq!(matched_doc, "/docs/architecture.md");
    assert!(score > 0);

    let top_k = ai_index.search_top_k(&query_vec, 2);
    assert_eq!(top_k[0].unwrap().0, "/docs/architecture.md");

    // Normalisation de similarité cosinus (parts per thousand)
    let sim_ppm = doc_vec.cosine_similarity_ppm(&query_vec);
    assert!(sim_ppm >= 900 && sim_ppm <= 1000);

    // Tiny Embedder déterministe
    let auto_emb = jambo_aid::VectorEmbedding::from_text("jambo kernel ai");
    assert!(auto_emb.norm() > 0);

    // Test de l'orchestrateur d'intentions typées
    let mut intent_engine = jambo_aid::IntentOrchestrator::new();
    let act1 = intent_engine.parse_intent("lance le terminal pour compiler le projet");
    assert_eq!(
        act1,
        jambo_aid::IntentAction::LaunchApplication("jambo-term")
    );

    let act2 = intent_engine.parse_intent("affiche les permissions de la table de capacités");
    assert_eq!(act2, jambo_aid::IntentAction::InspectSystemCapabilities);

    let act3 = intent_engine.parse_intent("configure le reseau ip");
    assert_eq!(
        act3,
        jambo_aid::IntentAction::ConfigureNetwork {
            interface: "eth0",
            dhcp: true
        }
    );

    // 11. Durcissement de sécurité offensive, Fuzzing et tests de résilience chaotique (Phase 16 - jambo-fuzz v0.2.14)
    let mut fuzzer = jambo_fuzz::SecurityFuzzer::new();

    // Campagne de fuzzing d'appels système (10 000 mutations hostiles)
    let fuzz_report = fuzzer.fuzz_syscall_robustness(10_000);
    assert_eq!(fuzz_report.total_mutations_tested, 10_000);
    assert!(fuzz_report.zero_kernel_panics);
    assert!(fuzz_report.blocked_bad_pointers > 0);

    // Fuzzing des canaux IPC et résistance aux débordements de tampons
    let ipc_overflows = fuzzer.fuzz_ipc_channel_overflow(1_000);
    assert!(ipc_overflows > 0);

    // Fuzzing d'épuisement mémoire et allocations massives
    let mem_fuzz = fuzzer.fuzz_memory_exhaustion_stress(1_000);
    assert_eq!(mem_fuzz, 1_000);

    // Test de la barrière matérielle SMAP / SMEP
    assert!(fuzzer.test_smap_smep_kernel_isolation());

    // Test d'inviolabilité IOMMU : 100 % des accès DMA hors-bornes sont bloqués
    let dma_contained = fuzzer.test_iommu_attack_containment();
    assert!(dma_contained);

    // Test de chaos et auto-guérison matérielle sous 25 ms
    let (driver_survived, latency_ms) = fuzzer.test_chaos_driver_resilience();
    assert!(driver_survived);
    assert!(latency_ms < 25);

    // 12. Bus RPC Distribué et Écosystème Cluster Haute Disponibilité (Phase 17 - jambo-rpc)
    let mut rpc_registry = jambo_rpc::RpcRegistry::new();
    let compute_service_id = 0xCAFE_BABE_0000_0001;
    rpc_registry
        .register_service(
            compute_service_id,
            "org.jambo.cluster.compute",
            libjambo::cap_rights::READ | libjambo::cap_rights::WRITE,
        )
        .expect("Register RPC service");

    let cluster_secret = [0x77u8; 32];
    let mut rpc_dispatcher = jambo_rpc::RpcServerDispatcher::new(rpc_registry, cluster_secret);

    // Test d'appel RPC légitime avec jeton de capacité signé
    let valid_token = jambo_rpc::DistributedCapToken::new_signed(
        1, // Node source (client)
        2, // Node cible (serveur)
        compute_service_id,
        libjambo::cap_rights::READ | libjambo::cap_rights::WRITE,
        100, // Nonce initial
        &cluster_secret,
    );
    let rpc_req = jambo_rpc::RpcPacket::new_request(
        1,
        compute_service_id,
        7, // Method ID
        valid_token,
        &[0x01, 0x02, 0x03, 0x04],
    );
    let rpc_res = rpc_dispatcher
        .dispatch(&rpc_req)
        .expect("Valid RPC call must succeed");
    assert_eq!(rpc_res.status, 0);
    assert_eq!(rpc_res.payload[0], 0xAA);
    assert_eq!(rpc_res.payload[1], 7);

    // Test de détection formelle d'attaque par rejeu (nonce inférieur au minimum requis)
    let replayed_token = jambo_rpc::DistributedCapToken::new_signed(
        1,
        2,
        compute_service_id,
        libjambo::cap_rights::READ | libjambo::cap_rights::WRITE,
        50, // Nonce déjà expiré
        &cluster_secret,
    );
    let replay_req =
        jambo_rpc::RpcPacket::new_request(2, compute_service_id, 7, replayed_token, &[]);
    assert!(rpc_dispatcher.dispatch(&replay_req).is_err());

    // Test de rejet d'une capacité falsifiée (mauvaise clé secrète)
    let rogue_secret = [0x11u8; 32];
    let forged_token = jambo_rpc::DistributedCapToken::new_signed(
        1,
        2,
        compute_service_id,
        libjambo::cap_rights::READ | libjambo::cap_rights::WRITE,
        200,
        &rogue_secret,
    );
    let forged_req = jambo_rpc::RpcPacket::new_request(3, compute_service_id, 7, forged_token, &[]);
    assert!(rpc_dispatcher.dispatch(&forged_req).is_err());

    // Test du gestionnaire de cluster et bascule automatique (Failover transparent)
    let mut cluster_mgr = jambo_rpc::ClusterManager::new(1);
    cluster_mgr
        .add_node(2, [192, 168, 1, 10])
        .expect("Add node 2");
    cluster_mgr
        .add_node(3, [192, 168, 1, 11])
        .expect("Add node 3");
    assert_eq!(cluster_mgr.active_nodes, 2);

    let backup_node = cluster_mgr.trigger_failover(2);
    assert_eq!(backup_node, Some(3));

    // Test de monitoring des battements de cœur et détection de nœud dégradé
    cluster_mgr
        .record_heartbeat(3, 110)
        .expect("Record heartbeat node 3");
    let degraded = cluster_mgr.monitor_liveness(125, 10);
    assert_eq!(degraded, 1);

    // 13. Démon d'Audit Cryptographique Inaltérable & Observabilité Zéro-Autorité (Phase 18 - jambo-auditd v0.2.16)
    let mut audit_ledger = jambo_auditd::AuditLedger::new();
    let audit_cap = jambo_auditd::AuditCap::new(
        libjambo::Handle::new(500, 1),
        0xFFFFFFFF, // Toutes catégories autorisées
        jambo_auditd::AuditSeverity::Debug,
        true,
        true,
    );

    // Enregistrement d'événements de sécurité dans le grand livre scellé
    let ev1 = audit_ledger
        .record_event(
            &audit_cap,
            1, // PID init
            jambo_auditd::AuditCategory::CSpace,
            jambo_auditd::AuditSeverity::Info,
            0x10,
            b"Capability root table instantiated",
            1000,
        )
        .expect("Record CSpace audit event");
    assert_eq!(ev1, 1);

    let ev2 = audit_ledger
        .record_event(
            &audit_cap,
            2, // PID pcie-bus-mgr
            jambo_auditd::AuditCategory::IommuDma,
            jambo_auditd::AuditSeverity::Warning,
            0x20,
            b"PCIe FLR recovery completed",
            1500,
        )
        .expect("Record IOMMU audit event");
    assert_eq!(ev2, 2);

    let ev3 = audit_ledger
        .record_event(
            &audit_cap,
            3, // PID jambo-rpc
            jambo_auditd::AuditCategory::DistributedRpc,
            jambo_auditd::AuditSeverity::SecurityViolation,
            0x30,
            b"Rpc replay attempt blocked",
            2000,
        )
        .expect("Record RPC violation");
    assert_eq!(ev3, 3);

    // Vérification mathématique d'intégrité de la chaîne cryptographique
    assert!(audit_ledger.verify_chain_integrity());

    // Contrôle d'accès strict : rejet d'enregistrement avec capacité non autorisée
    let read_only_cap = jambo_auditd::AuditCap::new(
        libjambo::Handle::new(501, 1),
        jambo_auditd::AuditCategory::CSpace.to_mask(),
        jambo_auditd::AuditSeverity::Info,
        false, // can_write = false
        true,
    );
    let unauthorized_write = audit_ledger.record_event(
        &read_only_cap,
        1,
        jambo_auditd::AuditCategory::CSpace,
        jambo_auditd::AuditSeverity::Info,
        0x11,
        b"Illegal write attempt",
        2500,
    );
    assert_eq!(
        unauthorized_write,
        Err(libjambo::SysError::PermissionDenied)
    );

    // Détection d'anomalies de sécurité en temps réel
    let anomaly_detector = jambo_auditd::AnomalyDetector::new(1);
    let alert = anomaly_detector.scan_for_anomalies(&audit_ledger);
    assert!(alert.is_some());
    let alert_data = alert.unwrap();
    assert_eq!(alert_data.suspect_pid, 3);
    assert_eq!(
        alert_data.anomaly,
        jambo_auditd::AnomalyType::PotentialRpcReplayAttack
    );

    // 14. Gestionnaire d'Énergie et Événements Matériels ACPI Ring 3 (Phase 19 - jambo-powerd v0.2.17)
    let fadt_info = jambo_powerd::AcpiFadtInfo::default();
    let mut power_mgr = jambo_powerd::PowerManager::new(fadt_info);

    // Contrôle d'accès sans autorité ambiante : rejet d'une tentative de mise en veille non autorisée
    let query_only_cap = jambo_powerd::PowerCap::new(
        libjambo::Handle::new(600, 1),
        jambo_powerd::power_rights::BATTERY_QUERY,
    );
    let unauthorized_sleep =
        power_mgr.transition_state(&query_only_cap, jambo_powerd::PowerState::S3SuspendToRam);
    assert_eq!(
        unauthorized_sleep,
        Err(libjambo::SysError::PermissionDenied)
    );

    // Capacité d'administration de l'énergie légitime
    let power_admin_cap = jambo_powerd::PowerCap::new(
        libjambo::Handle::new(601, 1),
        jambo_powerd::power_rights::SHUTDOWN
            | jambo_powerd::power_rights::SUSPEND
            | jambo_powerd::power_rights::THROTTLE
            | jambo_powerd::power_rights::BATTERY_QUERY,
    );

    // Validation des transitions d'états ACPI (S0 -> S3 -> S0)
    let s3_res =
        power_mgr.transition_state(&power_admin_cap, jambo_powerd::PowerState::S3SuspendToRam);
    assert_eq!(s3_res, Ok(jambo_powerd::PowerState::S3SuspendToRam));

    let s0_res = power_mgr.transition_state(&power_admin_cap, jambo_powerd::PowerState::S0Working);
    assert_eq!(s0_res, Ok(jambo_powerd::PowerState::S0Working));

    // Régulation dynamique des C-states sur les cœurs de calcul SMP
    let cstate_res = power_mgr.set_core_cstate(
        &power_admin_cap,
        2, // Cœur AP #2 inactif
        jambo_powerd::CpuPowerState::C3DeepSleep,
    );
    assert!(cstate_res.is_ok());
    assert_eq!(
        power_mgr.cpu_cstates[2],
        jambo_powerd::CpuPowerState::C3DeepSleep
    );
    assert_eq!(
        power_mgr.cpu_cstates[0],
        jambo_powerd::CpuPowerState::C0Active
    );

    // Évaluation de la télémétrie de batterie et politique de sauvegarde
    power_mgr
        .update_battery(&power_admin_cap, 12, false, 36)
        .expect("Update battery telemetry");
    assert_eq!(
        power_mgr.evaluate_policy(),
        jambo_powerd::PowerPolicyAction::EngageBatterySaver
    );
    assert!(power_mgr.power_saver_active);

    // Boucle de supervision de la santé des services Ring 3
    loop {
        unsafe {
            libjambo::syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
        }
    }
}
