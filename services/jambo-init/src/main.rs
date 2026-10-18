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

    // 15. Chiffrement de Bloc Transparent et Scellement Matériel TPM (Phase 20 - jambo-cryptod v0.2.18)
    let master_volume_key = [0x5Cu8; 32];
    let mut enc_dev = jambo_cryptod::EncryptedBlockDevice::new(1, master_volume_key);

    let crypto_cap = jambo_cryptod::CryptoVolumeCap::new(
        libjambo::Handle::new(700, 1),
        1,
        jambo_cryptod::crypto_rights::READ_SECTOR
            | jambo_cryptod::crypto_rights::WRITE_SECTOR
            | jambo_cryptod::crypto_rights::ROTATE_KEY
            | jambo_cryptod::crypto_rights::SEAL_TPM,
    );

    // Chiffrement d'un secteur de données JamboFS
    let raw_sector = [0x7Eu8; jambo_cryptod::SECTOR_SIZE];
    let mut enc_sector0 = [0u8; jambo_cryptod::SECTOR_SIZE];
    let mut enc_sector1 = [0u8; jambo_cryptod::SECTOR_SIZE];

    enc_dev
        .encrypt_and_write(&crypto_cap, 0, &raw_sector, &mut enc_sector0)
        .expect("Encrypt sector LBA 0");
    enc_dev
        .encrypt_and_write(&crypto_cap, 1, &raw_sector, &mut enc_sector1)
        .expect("Encrypt sector LBA 1");

    // Propriété anti-motif LBA : les ciphertexts diffèrent malgré un contenu identique
    assert_ne!(&enc_sector0[..], &raw_sector[..]);
    assert_ne!(&enc_sector0[..], &enc_sector1[..]);

    // Déchiffrement transparent exact
    let mut dec_sector = [0u8; jambo_cryptod::SECTOR_SIZE];
    enc_dev
        .read_and_decrypt(&crypto_cap, 0, &enc_sector0, &mut dec_sector)
        .expect("Decrypt sector LBA 0");
    assert_eq!(&dec_sector[..], &raw_sector[..]);

    // Scellement TPM 2.0 sous les registres PCR de démarrage mesuré
    let measured_pcrs: [[u8; 32]; 8] = [
        [0xA0; 32], [0xA1; 32], [0xA2; 32], [0xA3; 32], [0xA4; 32], // Limine
        [0xA5; 32], [0xA6; 32], [0xA7; 32],
    ];
    enc_dev
        .seal_with_tpm(&crypto_cap, &measured_pcrs)
        .expect("Seal volume under TPM PCRs");
    assert!(enc_dev.sealed_blob.is_some());

    // Vérification du descellement TPM sur plateforme intègre
    let unsealed =
        jambo_cryptod::TpmSealEngine::unseal(enc_dev.sealed_blob.as_ref().unwrap(), &measured_pcrs)
            .expect("Unseal TPM key");
    assert_eq!(unsealed, master_volume_key);

    // Rejet formel du descellement si un PCR est altéré (attaque sur le bootloader)
    let mut tampered_pcrs = measured_pcrs;
    tampered_pcrs[4][0] ^= 0xFF;
    let tamper_fail =
        jambo_cryptod::TpmSealEngine::unseal(enc_dev.sealed_blob.as_ref().unwrap(), &tampered_pcrs);
    assert_eq!(tamper_fail, Err(libjambo::SysError::PermissionDenied));

    // Contrôle de capacité : rejet strict en écriture sans droit WRITE_SECTOR
    let read_only_crypto_cap = jambo_cryptod::CryptoVolumeCap::new(
        libjambo::Handle::new(701, 1),
        1,
        jambo_cryptod::crypto_rights::READ_SECTOR,
    );
    let bad_write =
        enc_dev.encrypt_and_write(&read_only_crypto_cap, 2, &raw_sector, &mut enc_sector0);
    assert_eq!(bad_write, Err(libjambo::SysError::PermissionDenied));

    // 16. Identité Cryptographique et Gestionnaire de Sessions Isolées (Phase 21 - jambo-authd v0.2.19)
    let mut session_mgr = jambo_authd::SessionManager::new();
    let bob_key = [0x99u8; 32];
    let bob_identity = jambo_authd::UserIdentity::new(
        1002,
        "bob",
        bob_key,
        jambo_authd::UserRole::SystemOperator,
        0xFFFF,
    );
    session_mgr
        .register_user(bob_identity)
        .expect("Register user bob");

    // Défi-réponse cryptographique
    let auth_challenge = jambo_authd::CryptoAuthEngine::generate_challenge(0x5EED, 1);
    let valid_signature = jambo_authd::CryptoAuthEngine::sign_challenge(&bob_key, &auth_challenge);

    // Authentification légitime
    let bob_session = session_mgr
        .authenticate("bob", &auth_challenge, &valid_signature, 10_000, 30_000)
        .expect("Authenticate bob");
    assert_eq!(bob_session.user_id, 1002);
    assert_eq!(bob_session.role, jambo_authd::UserRole::SystemOperator);
    assert!(session_mgr.validate_session(&bob_session, 15_000).is_ok());

    // Rejet formel d'une signature falsifiée
    let mut forged_signature = valid_signature;
    forged_signature[0] ^= 0xEE;
    let auth_fail =
        session_mgr.authenticate("bob", &auth_challenge, &forged_signature, 10_000, 30_000);
    assert_eq!(auth_fail, Err(libjambo::SysError::PermissionDenied));

    // Déconnexion et révocation atomique (Zero-Remanence)
    session_mgr
        .terminate_session(bob_session.session_id)
        .expect("Terminate session");
    assert_eq!(
        session_mgr.validate_session(&bob_session, 15_000),
        Err(libjambo::SysError::InvalidHandle)
    );

    // 17. Moniteur de Micro-Machines Virtuelles et Isolation Matérielle Type-2 (Phase 22 - jambo-vmm v0.2.20)
    let vmm_cap = jambo_vmm::VmCap::new(
        libjambo::Handle::new(801, 1),
        101,
        jambo_vmm::vm_rights::ALL,
    );
    let mut micro_vmm = jambo_vmm::MicroVmm::new(&vmm_cap, 101).expect("Create MicroVMM");

    // Configuration de la mémoire imbriquée EPT
    micro_vmm
        .map_memory(&vmm_cap, 0x0, 0x100000, 0x2000, jambo_vmm::ept_perms::RWX)
        .expect("Map guest memory");

    // Instanciation d'un processeur virtuel vCPU
    micro_vmm
        .add_vcpu(&vmm_cap, 0, 0x0, 0x1000)
        .expect("Add vCPU 0");

    // Payload invité : écriture série COM1 et extinction
    let mut guest_code = [0u8; 0x2000];
    guest_code[0] = 0xB8; // MOV EAX, 0x4F ('O')
    guest_code[1] = b'O';
    guest_code[2] = 0x00;
    guest_code[3] = 0x00;
    guest_code[4] = 0x00;
    guest_code[5] = 0xE6; // OUT 0xF8, AL
    guest_code[6] = 0xF8;
    guest_code[7] = 0xB8; // MOV EAX, 0x4B ('K')
    guest_code[8] = b'K';
    guest_code[9] = 0x00;
    guest_code[10] = 0x00;
    guest_code[11] = 0x00;
    guest_code[12] = 0xE6; // OUT 0xF8, AL
    guest_code[13] = 0xF8;
    guest_code[14] = 0xF4; // HLT

    // Exécution pas-à-pas avec piégeage matériel
    assert_eq!(
        micro_vmm
            .step_vcpu(&vmm_cap, 0, &guest_code)
            .expect("Step MOV 1"),
        jambo_vmm::VmExitReason::CpuidQuery {
            leaf: b'O' as u32,
            subleaf: 0
        }
    );
    assert_eq!(
        micro_vmm
            .step_vcpu(&vmm_cap, 0, &guest_code)
            .expect("Step OUT 1"),
        jambo_vmm::VmExitReason::IoInstruction {
            port: 0xF8,
            is_write: true,
            size: 1,
            data: b'O' as u32
        }
    );
    assert_eq!(
        micro_vmm
            .step_vcpu(&vmm_cap, 0, &guest_code)
            .expect("Step MOV 2"),
        jambo_vmm::VmExitReason::CpuidQuery {
            leaf: b'K' as u32,
            subleaf: 0
        }
    );
    assert_eq!(
        micro_vmm
            .step_vcpu(&vmm_cap, 0, &guest_code)
            .expect("Step OUT 2"),
        jambo_vmm::VmExitReason::IoInstruction {
            port: 0xF8,
            is_write: true,
            size: 1,
            data: b'K' as u32
        }
    );
    assert_eq!(
        micro_vmm
            .step_vcpu(&vmm_cap, 0, &guest_code)
            .expect("Step HLT"),
        jambo_vmm::VmExitReason::Halt
    );

    // Contrôle d'accès sans privilège de virtualisation
    let unauth_vmm_cap = jambo_vmm::VmCap::new(libjambo::Handle::new(802, 1), 101, 0);
    assert_eq!(
        micro_vmm.step_vcpu(&unauth_vmm_cap, 0, &guest_code),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 18. Virtualisation de Périphériques vhost-user Découplés (Phase 23 - jambo-vhostd v0.2.21)
    let vhost_cap = jambo_vhostd::VhostCap::new(
        libjambo::Handle::new(901, 1),
        10,
        jambo_vhostd::vhost_rights::ALL,
    );
    let mut vhost_server = jambo_vhostd::VhostServer::new();

    // Enregistrement d'un backend réseau virtuel VirtIO-Net
    vhost_server
        .register_net_device(&vhost_cap, 10, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
        .expect("Register vhost-net device");

    // Négociation vhost-user : configuration de virtqueue
    vhost_server
        .dispatch_request(
            &vhost_cap,
            10,
            jambo_vhostd::VhostUserRequest::SetVringNum { index: 0, num: 128 },
        )
        .expect("Configure vhost virtqueue");

    // Transmission et réception de paquets réseau isolés
    let net_dev = vhost_server.net_devices[0].as_mut().expect("Net device");
    let test_frame = b"JAMBO_VHOST_USER_ETHERNET_PAYLOAD";
    net_dev
        .transmit_packet(&vhost_cap, test_frame)
        .expect("Transmit guest frame");
    assert_eq!(net_dev.tx_packets_count, 1);

    let mut guest_rx_buf = [0u8; 64];
    let rx_len = net_dev
        .receive_packet(&vhost_cap, &mut guest_rx_buf, test_frame)
        .expect("Receive guest frame");
    assert_eq!(&guest_rx_buf[..rx_len], test_frame);
    assert_eq!(net_dev.rx_packets_count, 1);

    // Contrôle d'accès : rejet immédiat en l'absence de VhostCap autorisée
    let unauth_vhost_cap = jambo_vhostd::VhostCap::new(libjambo::Handle::new(902, 1), 10, 0);
    assert_eq!(
        net_dev.transmit_packet(&unauth_vhost_cap, test_frame),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 19. Synchronisation Horlogère Distribuée PTP/NTP (Phase 24 - jambo-timed v0.2.22)
    let time_cap = jambo_timed::TimeSyncCap::new(
        libjambo::Handle::new(1001, 1),
        1,
        jambo_timed::time_rights::ALL,
    );
    let mut time_server =
        jambo_timed::TimeSyncServer::new(1, jambo_timed::PreciseTime::new(1792340000, 0));

    // Lecture du temps garanti
    let t_init = time_server.read_time(&time_cap).expect("Read precise time");
    assert_eq!(t_init.seconds, 1792340000);

    // Synchronisation d'un échantillon PTP (IEEE 1588)
    let ptp_sample = jambo_timed::PtpSample {
        t1_master_tx: jambo_timed::PreciseTime::new(1792340000, 0),
        t2_slave_rx: jambo_timed::PreciseTime::new(1792340000, 15_000_000),
        t3_slave_tx: jambo_timed::PreciseTime::new(1792340000, 20_000_000),
        t4_master_rx: jambo_timed::PreciseTime::new(1792340000, 25_000_000),
    };
    let (offset, delay) = time_server
        .apply_ptp_sync(&time_cap, &ptp_sample)
        .expect("Apply PTP sync");
    assert_eq!(offset, 5_000_000); // 5 ms offset
    assert_eq!(delay, 10_000_000); // 10 ms delay
    assert_eq!(time_server.sync_count, 1);

    // Progression monotone stricte de l'horloge
    let t_next = time_server.advance_time(1_000_000);
    assert!(t_next.as_nanos() > t_init.as_nanos());

    // Contrôle d'accès : rejet strict de synchronisation sans TimeSyncCap
    let unauth_time_cap = jambo_timed::TimeSyncCap::new(libjambo::Handle::new(1002, 1), 1, 0);
    assert_eq!(
        time_server.apply_ptp_sync(&unauth_time_cap, &ptp_sample),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 20. Moteur de Consensus Distribué Léger Raft (Phase 25 - jambo-raft v0.2.23)
    let raft_cap = jambo_raft::RaftCap::new(
        libjambo::Handle::new(1101, 1),
        42,
        jambo_raft::raft_rights::ALL,
    );
    let mut leader_node = jambo_raft::RaftNode::new(1, 42);

    // Élection de leader
    let vote_req = leader_node
        .start_election(&raft_cap)
        .expect("Start Raft election");
    assert_eq!(leader_node.role, jambo_raft::RaftRole::Candidate);

    let vote_reply = jambo_raft::RequestVoteReply {
        term: vote_req.term,
        vote_granted: true,
    };
    leader_node.record_vote(&raft_cap, &vote_reply, 3);
    assert_eq!(leader_node.role, jambo_raft::RaftRole::Leader);

    // Proposition et réplication de commande de cluster
    let log_entry = leader_node
        .propose_command(&raft_cap, 501, b"JAMBO_CLUSTER_COMMIT")
        .expect("Propose Raft command");
    assert_eq!(log_entry.index, 1);

    // Réplication sur un nœud suiveur
    let mut follower_node = jambo_raft::RaftNode::new(2, 42);
    let append_args = jambo_raft::AppendEntriesArgs {
        term: leader_node.current_term,
        leader_id: 1,
        prev_log_index: 0,
        prev_log_term: 0,
        entry: Some(log_entry),
        leader_commit: 1,
    };
    let append_reply = follower_node
        .handle_append_entries(&raft_cap, &append_args)
        .expect("Replicate Raft entry");
    assert!(append_reply.success);
    assert_eq!(follower_node.commit_index, 1);
    assert_eq!(follower_node.apply_committed(), 1);

    // Contrôle d'accès : rejet immédiat sans RaftCap autorisée
    let unauth_raft_cap = jambo_raft::RaftCap::new(libjambo::Handle::new(1102, 1), 42, 0);
    assert_eq!(
        leader_node.propose_command(&unauth_raft_cap, 502, b"UNAUTHORIZED"),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 21. Magasin Clé-Valeur Distribué Transactionnel (Phase 26 - jambo-kvd v0.2.24)
    let kv_cap = jambo_kvd::KvCap::new(libjambo::Handle::new(1201, 1), jambo_kvd::kv_rights::ALL);
    let mut kv_store = jambo_kvd::KvStore::new();

    // Insertion et validation MVCC
    let rev1 = kv_store
        .put(&kv_cap, b"cluster/config/mtu", b"9000", None)
        .expect("KV Put MTU");
    assert_eq!(rev1, 1);

    let val = kv_store
        .get(&kv_cap, b"cluster/config/mtu")
        .expect("KV Get MTU");
    assert_eq!(val.unwrap().value_bytes(), b"9000");

    // Baux temporels et expiration automatique
    let lease_id = kv_store
        .grant_lease(&kv_cap, 500, 1000)
        .expect("Grant KV lease");
    kv_store
        .put(
            &kv_cap,
            b"services/discovery/vmm",
            b"active",
            Some(lease_id),
        )
        .expect("Put KV with lease");

    // Purge à expiration (t=1600 > 1000 + 500)
    let purged = kv_store.purge_expired_leases(1600);
    assert_eq!(purged, 1);
    assert!(kv_store
        .get(&kv_cap, b"services/discovery/vmm")
        .unwrap()
        .is_none());

    // Transaction atomique Compare-And-Swap (CAS)
    let cmp = [jambo_kvd::KvCompare::new(
        b"cluster/config/mtu",
        jambo_kvd::CompareTarget::from_value_bytes(b"9000"),
        jambo_kvd::CompareOp::Equal,
    )];
    let success_ops = [jambo_kvd::KvOp::new_put(
        b"cluster/config/mtu",
        b"1500",
        None,
    )];
    let failure_ops = [];
    let txn_res = kv_store
        .txn(&kv_cap, &cmp, &success_ops, &failure_ops)
        .expect("KV Txn CAS");
    assert!(txn_res.succeeded);
    assert_eq!(
        kv_store
            .get(&kv_cap, b"cluster/config/mtu")
            .unwrap()
            .unwrap()
            .value_bytes(),
        b"1500"
    );

    // Contrôle d'accès : rejet immédiat sans KvCap autorisée
    let unauth_kv_cap = jambo_kvd::KvCap::new(libjambo::Handle::new(1202, 1), 0);
    assert_eq!(
        kv_store.put(&unauth_kv_cap, b"unauthorized", b"data", None),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 22. Ordonnanceur de Charges de Travail et de Conteneurs Distribués (Phase 27 - jambo-schedd v0.2.25)
    let sched_cap = jambo_schedd::SchedCap::new(
        libjambo::Handle::new(1301, 1),
        jambo_schedd::sched_rights::ALL,
    );
    let mut cluster_sched = jambo_schedd::ClusterScheduler::new();

    // Enregistrement des nœuds de la grappe
    cluster_sched
        .register_node(&sched_cap, 1, 16, 2048)
        .expect("Register cluster node 1");
    cluster_sched
        .register_node(&sched_cap, 2, 16, 2048)
        .expect("Register cluster node 2");

    // Soumission déclarative d'une micro-VM et d'un conteneur WASM
    let vmm_spec = jambo_schedd::TaskSpec::new(
        0,
        b"micro-vmm-gateway",
        jambo_schedd::RuntimeType::MicroVmm,
        4,
        512,
        Some(1),
    );
    let wasm_spec = jambo_schedd::TaskSpec::new(
        0,
        b"wasm-edge-filter",
        jambo_schedd::RuntimeType::Wasm,
        2,
        128,
        None,
    );
    let vmm_tid = cluster_sched
        .submit_task(&sched_cap, vmm_spec)
        .expect("Submit VMM task");
    let wasm_tid = cluster_sched
        .submit_task(&sched_cap, wasm_spec)
        .expect("Submit WASM task");

    // Ordonnancement et placement déclaratif
    let placed = cluster_sched.schedule_pending(1000);
    assert_eq!(placed, 2);

    let vmm_task = cluster_sched
        .query_task(&sched_cap, vmm_tid)
        .expect("Query VMM task");
    assert_eq!(vmm_task.state, jambo_schedd::TaskState::Running);
    assert_eq!(vmm_task.assigned_node, Some(1));

    let wasm_task = cluster_sched
        .query_task(&sched_cap, wasm_tid)
        .expect("Query WASM task");
    assert_eq!(wasm_task.state, jambo_schedd::TaskState::Running);
    assert!(wasm_task.assigned_node.is_some());

    // Migration à chaud et drainage contrôlé
    cluster_sched
        .migrate_task(&sched_cap, vmm_tid, 2)
        .expect("Migrate VMM task to node 2");
    assert_eq!(
        cluster_sched
            .query_task(&sched_cap, vmm_tid)
            .unwrap()
            .assigned_node,
        Some(2)
    );

    // Contrôle d'accès : rejet strict sans SchedCap autorisée
    let unauth_sched_cap = jambo_schedd::SchedCap::new(libjambo::Handle::new(1302, 1), 0);
    assert_eq!(
        cluster_sched.cancel_task(&unauth_sched_cap, vmm_tid),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 23. Bus d'Événements Pub/Sub Asynchrone Zéro-Copie (Phase 28 - jambo-eventd v0.2.26)
    let event_cap = jambo_eventd::EventCap::new(
        libjambo::Handle::new(1401, 1),
        jambo_eventd::event_rights::ALL,
    );
    let mut event_bus = jambo_eventd::EventBus::new();

    // Enregistrement d'abonnements (exact et par préfixe)
    let sub_sched = event_bus
        .subscribe(&event_cap, b"scheduler/", true)
        .expect("Subscribe scheduler events");
    let sub_audit = event_bus
        .subscribe(&event_cap, b"security/audit", false)
        .expect("Subscribe audit events");

    // Publication d'événements asynchrones
    let seq1 = event_bus
        .publish(
            &event_cap,
            1,
            b"scheduler/node_drain",
            b"NODE_2_DRAINED",
            1000,
        )
        .expect("Publish scheduler event");
    assert_eq!(seq1, 1);

    let seq2 = event_bus
        .publish(
            &event_cap,
            1,
            b"security/audit",
            b"UNAUTH_ACCESS_BLOCKED",
            1001,
        )
        .expect("Publish audit event");
    assert_eq!(seq2, 2);

    // Consommation et vérification d'isolation
    let sched_ev = event_bus
        .poll_event(&event_cap, sub_sched)
        .expect("Poll scheduler event");
    assert_eq!(sched_ev.unwrap().payload_bytes(), b"NODE_2_DRAINED");

    let audit_ev = event_bus
        .poll_event(&event_cap, sub_audit)
        .expect("Poll audit event");
    assert_eq!(audit_ev.unwrap().payload_bytes(), b"UNAUTH_ACCESS_BLOCKED");

    // Contrôle d'accès : rejet strict sans EventCap autorisée
    let unauth_event_cap = jambo_eventd::EventCap::new(libjambo::Handle::new(1402, 1), 0);
    assert_eq!(
        event_bus.publish(&unauth_event_cap, 1, b"unauthorized", b"data", 1002),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 24. Maillage Réseau Chiffré Distribué & Routage Zero-Trust (Phase 29 - jambo-meshd v0.2.27)
    let mesh_cap = jambo_meshd::MeshCap::new(
        libjambo::Handle::new(1501, 1),
        jambo_meshd::mesh_rights::ALL,
    );
    let mut local_mesh = jambo_meshd::MeshNetwork::new(1, [10, 42, 0, 1]);
    let mut remote_mesh = jambo_meshd::MeshNetwork::new(2, [10, 42, 0, 2]);

    let session_key = [0x5A; 32];
    local_mesh
        .add_peer(
            &mesh_cap,
            2,
            &[0x02; 32],
            [10, 42, 0, 2],
            ([192, 168, 1, 20], 51820),
            &session_key,
        )
        .expect("Add mesh peer 2");
    remote_mesh
        .add_peer(
            &mesh_cap,
            1,
            &[0x01; 32],
            [10, 42, 0, 1],
            ([192, 168, 1, 10], 51820),
            &session_key,
        )
        .expect("Add mesh peer 1");

    // Encapsulation et chiffrement de bout en bout
    let plaintext_payload = b"JAMBO_ZERO_TRUST_ENCRYPTED_PACKET";
    let encrypted_pkt = local_mesh
        .encapsulate_and_encrypt(&mesh_cap, [10, 42, 0, 2], plaintext_payload)
        .expect("Encapsulate and encrypt mesh packet");
    assert_ne!(encrypted_pkt.data_bytes(), plaintext_payload);

    // Déchiffrement et vérification d'intégrité
    let mut decrypted_buf = [0u8; 64];
    let dec_len = remote_mesh
        .decrypt_and_decapsulate(&mesh_cap, &encrypted_pkt, &mut decrypted_buf)
        .expect("Decrypt mesh packet");
    assert_eq!(&decrypted_buf[..dec_len], plaintext_payload);

    // Contrôle d'accès : rejet strict sans MeshCap autorisée
    let unauth_mesh_cap = jambo_meshd::MeshCap::new(libjambo::Handle::new(1502, 1), 0);
    assert_eq!(
        local_mesh.encapsulate_and_encrypt(&unauth_mesh_cap, [10, 42, 0, 2], b"test"),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 25. Système de Fichiers Distribué Adressable par Contenu & Réplication (Phase 30 - jambo-dfsd v0.2.28)
    let dfs_cap =
        jambo_dfsd::DfsCap::new(libjambo::Handle::new(1601, 1), jambo_dfsd::dfs_rights::ALL);
    let mut dfs_store = jambo_dfsd::DfsBlockStore::new(1);
    let block_data = b"JAMBO_DISTRIBUTED_CONTENT_ADDRESSED_OBJECT_PAYLOAD";
    let block_hash = dfs_store
        .put_block(&dfs_cap, block_data, true)
        .expect("Put CAS block in jambo-dfsd");

    // Déduplication CAS
    let dup_hash = dfs_store
        .put_block(&dfs_cap, block_data, false)
        .expect("Put duplicate CAS block");
    assert_eq!(block_hash, dup_hash);
    assert_eq!(dfs_store.dedup_count, 1);
    assert_eq!(dfs_store.block_count(), 1);

    // Lecture avec vérification d'intégrité
    let mut read_buf = [0u8; 128];
    let read_bytes = dfs_store
        .get_block(&dfs_cap, &block_hash, &mut read_buf)
        .expect("Get CAS block with integrity check");
    assert_eq!(&read_buf[..read_bytes], block_data);

    // Réplication multi-nœuds et protection par épinglage (pin)
    dfs_store
        .add_replica(&dfs_cap, &block_hash, 2)
        .expect("Add node 2 replica");
    assert_eq!(dfs_store.replica_count(&block_hash).unwrap(), 2);
    assert_eq!(
        dfs_store.delete_block(&dfs_cap, &block_hash),
        Err(libjambo::SysError::ResourceBusy)
    );

    // Contrôle d'accès sans autorité ambiante
    let unauth_dfs_cap = jambo_dfsd::DfsCap::new(libjambo::Handle::new(1602, 1), 0);
    assert_eq!(
        dfs_store.put_block(&unauth_dfs_cap, b"unauth", false),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 26. Passerelle Réseau L4/L7 & Équilibreur de Charge Élastique (Phase 31 - jambo-gwd v0.2.29)
    let gw_cap =
        jambo_gwd::GatewayCap::new(libjambo::Handle::new(1701, 1), jambo_gwd::gw_rights::ALL);
    let mut gw = jambo_gwd::GatewayManager::new();
    gw.register_service(
        &gw_cap,
        201,
        8080,
        jambo_gwd::LoadBalanceStrategy::LeastConnections,
        2, // Seuil coupe-circuit
    )
    .expect("Register virtual service 8080");

    gw.add_backend(&gw_cap, 201, [10, 0, 2, 1], 9001, 1)
        .expect("Add backend 1");
    gw.add_backend(&gw_cap, 201, [10, 0, 2, 2], 9002, 1)
        .expect("Add backend 2");

    // Routage Least-Connections
    let target1 = gw
        .route_packet(&gw_cap, 8080, [192, 168, 1, 100])
        .expect("Route connection 1");
    assert_eq!(target1, ([10, 0, 2, 1], 9001));

    let target2 = gw
        .route_packet(&gw_cap, 8080, [192, 168, 1, 101])
        .expect("Route connection 2");
    assert_eq!(target2, ([10, 0, 2, 2], 9002));

    // Coupe-circuit sur défaillance de backend
    gw.report_health(&gw_cap, 201, [10, 0, 2, 1], 9001, false)
        .expect("Report failure 1");
    let is_healthy = gw
        .report_health(&gw_cap, 201, [10, 0, 2, 1], 9001, false)
        .expect("Report failure 2");
    assert!(!is_healthy); // Circuit breaker activé

    // Requête suivante automatiquement basculée sur le nœud sain survivant
    let failover_target = gw
        .route_packet(&gw_cap, 8080, [192, 168, 1, 102])
        .expect("Failover to surviving node");
    assert_eq!(failover_target, ([10, 0, 2, 2], 9002));

    // Contrôle d'accès sans autorité ambiante
    let unauth_gw_cap = jambo_gwd::GatewayCap::new(libjambo::Handle::new(1702, 1), 0);
    assert_eq!(
        gw.route_packet(&unauth_gw_cap, 8080, [192, 168, 1, 103]),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 27. Coffre-Fort de Secrets Distribué & Déverrouillage par Quorum (Phase 32 - jambo-vaultd v0.2.30)
    let vault_cap = jambo_vaultd::VaultCap::new(
        libjambo::Handle::new(1801, 1),
        jambo_vaultd::vault_rights::ALL,
    );
    let master_seed = [0x55; 32];
    let mut vault = jambo_vaultd::VaultManager::new(2, 3, master_seed);

    // Déverrouillage progressif par parts de quorum (2 sur 3 nécessaires)
    let state1 = vault
        .submit_unseal_share(&vault_cap, 0, &[0xAA; 32])
        .expect("Submit share 0");
    assert_eq!(state1, jambo_vaultd::VaultState::Unsealing);

    let state2 = vault
        .submit_unseal_share(&vault_cap, 1, &[0xBB; 32])
        .expect("Submit share 1");
    assert_eq!(state2, jambo_vaultd::VaultState::Unsealed);

    // Enregistrement d'un secret sous chiffrement d'enveloppe
    let secret_path = b"cluster/root_ca_private_key";
    let secret_data = b"TOP_SECRET_CLUSTER_ED25519_KEY_MATERIAL";
    let v1 = vault
        .put_secret(&vault_cap, secret_path, secret_data, 7200, 1000)
        .expect("Store secret in vault");
    assert_eq!(v1, 1);

    // Lecture et déchiffrement vérifié
    let mut secret_buf = [0u8; 64];
    let (s_len, ver) = vault
        .get_secret(&vault_cap, secret_path, 1500, &mut secret_buf)
        .expect("Retrieve secret from vault");
    assert_eq!(ver, 1);
    assert_eq!(&secret_buf[..s_len], secret_data);

    // Contrôle d'accès sans autorité ambiante
    let unauth_vault_cap = jambo_vaultd::VaultCap::new(libjambo::Handle::new(1802, 1), 0);
    assert_eq!(
        vault.get_secret(&unauth_vault_cap, secret_path, 1500, &mut secret_buf),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 28. Moteur de Métriques Distribuées & Surveillance en Séries Temporelles (Phase 33 - jambo-metricsd v0.2.31)
    let metrics_cap = jambo_metricsd::MetricsCap::new(
        libjambo::Handle::new(1901, 1),
        jambo_metricsd::metrics_rights::ALL,
    );
    let mut collector = jambo_metricsd::MetricsCollector::new();

    collector
        .register_series(&metrics_cap, b"cluster_cpu_load", 1)
        .expect("Register CPU series");
    collector
        .register_alert(
            &metrics_cap,
            b"cluster_cpu_load",
            jambo_metricsd::AlertCondition::GreaterThan,
            85,
        )
        .expect("Register CPU alert rule");

    // Ingestion d'échantillons
    assert!(!collector
        .ingest(&metrics_cap, b"cluster_cpu_load", 1, 1000, 45)
        .expect("Ingest sample 1"));
    assert!(!collector
        .ingest(&metrics_cap, b"cluster_cpu_load", 1, 1001, 65)
        .expect("Ingest sample 2"));
    // Franchissement du seuil (90 > 85) -> alerte déclenchée
    assert!(collector
        .ingest(&metrics_cap, b"cluster_cpu_load", 1, 1002, 90)
        .expect("Ingest sample 3"));
    assert!(collector
        .is_alert_triggered(&metrics_cap, b"cluster_cpu_load")
        .unwrap());

    // Requête de statistiques
    let (min, max, avg, last, count) = collector
        .query_stats(&metrics_cap, b"cluster_cpu_load", 1)
        .expect("Query CPU stats");
    assert_eq!(min, 45);
    assert_eq!(max, 90);
    assert_eq!(avg, 66); // (45 + 65 + 90) / 3 = 66
    assert_eq!(last, 90);
    assert_eq!(count, 3);

    // Contrôle d'accès sans autorité ambiante
    let unauth_metrics_cap = jambo_metricsd::MetricsCap::new(libjambo::Handle::new(1902, 1), 0);
    assert_eq!(
        collector.ingest(&unauth_metrics_cap, b"cluster_cpu_load", 1, 1003, 50),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 29. Découverte de Services Distribuée & Résolution de Noms (Phase 34 - jambo-serviced v0.2.32)
    let discovery_cap = jambo_serviced::DiscoveryCap::new(
        libjambo::Handle::new(2001, 1),
        jambo_serviced::discovery_rights::ALL,
    );
    let mut reg = jambo_serviced::ServiceRegistry::new();

    reg.register_instance(
        &discovery_cap,
        b"vault.cluster",
        1,
        [10, 42, 1, 1],
        8200,
        1,
        60,
        1000,
    )
    .expect("Register vault instance 1");

    reg.register_instance(
        &discovery_cap,
        b"vault.cluster",
        2,
        [10, 42, 1, 2],
        8200,
        2,
        60,
        1000,
    )
    .expect("Register vault instance 2");

    // Résolution d'endpoints
    let mut endpoints = [([0u8; 4], 0u16); 4];
    let resolved_count = reg
        .resolve(&discovery_cap, b"vault.cluster", 1010, &mut endpoints)
        .expect("Resolve vault service endpoints");
    assert_eq!(resolved_count, 2);
    assert_eq!(endpoints[0], ([10, 42, 1, 1], 8200));
    assert_eq!(endpoints[1], ([10, 42, 1, 2], 8200));

    // Contrôle d'accès sans autorité ambiante
    let unauth_disc_cap = jambo_serviced::DiscoveryCap::new(libjambo::Handle::new(2002, 1), 0);
    assert_eq!(
        reg.register_instance(
            &unauth_disc_cap,
            b"fake.service",
            9,
            [0, 0, 0, 0],
            80,
            1,
            60,
            1000
        ),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 30. Moteur de Politiques de Sécurité Déclaratives & Contrôle d'Admission (Phase 35 - jambo-policyd v0.2.33)
    let policy_cap = jambo_policyd::PolicyCap::new(
        libjambo::Handle::new(2101, 1),
        jambo_policyd::policy_rights::ALL,
    );
    let mut pol_engine = jambo_policyd::PolicyEngine::new();

    // Règle 1 : Autorisation des charges de travail générales pour les opérateurs
    let allow_rule = jambo_policyd::PolicyRule::new(
        1,
        jambo_policyd::roles::ROLE_OPERATOR,
        jambo_policyd::actions::ACTION_SPAWN_WORKLOAD,
        b"workloads/",
        jambo_policyd::PolicyEffect::Allow,
        10,
        0,
    )
    .expect("Create allow rule");
    pol_engine
        .add_rule(&policy_cap, allow_rule)
        .expect("Add allow rule");

    // Règle 2 : Refus explicite prioritaire sur workloads/restricted
    let deny_rule = jambo_policyd::PolicyRule::new(
        2,
        jambo_policyd::roles::ROLE_OPERATOR,
        jambo_policyd::actions::ACTION_SPAWN_WORKLOAD,
        b"workloads/restricted",
        jambo_policyd::PolicyEffect::Deny,
        20,
        0,
    )
    .expect("Create deny rule");
    pol_engine
        .add_rule(&policy_cap, deny_rule)
        .expect("Add deny rule");

    // Admission légitime
    let req_ok = jambo_policyd::AdmissionRequest::new(
        501,
        jambo_policyd::roles::ROLE_OPERATOR,
        jambo_policyd::actions::ACTION_SPAWN_WORKLOAD,
        b"workloads/microvm-app",
        1000,
    )
    .expect("Create admission req");
    let dec_ok = pol_engine
        .evaluate(&policy_cap, &req_ok)
        .expect("Evaluate ok req");
    assert_eq!(dec_ok, jambo_policyd::AdmissionDecision::Allowed);

    // Admission rejetée par règle explicite Deny
    let req_restricted = jambo_policyd::AdmissionRequest::new(
        502,
        jambo_policyd::roles::ROLE_OPERATOR,
        jambo_policyd::actions::ACTION_SPAWN_WORKLOAD,
        b"workloads/restricted/db",
        1000,
    )
    .expect("Create restricted req");
    let dec_restricted = pol_engine
        .evaluate(&policy_cap, &req_restricted)
        .expect("Evaluate restricted req");
    assert_eq!(
        dec_restricted,
        jambo_policyd::AdmissionDecision::Denied {
            reason: "Explicit policy Deny matched",
            matching_rule_id: Some(2)
        }
    );

    // Admission rejetée par Deny-by-default
    let req_uncovered = jambo_policyd::AdmissionRequest::new(
        503,
        jambo_policyd::roles::ROLE_GUEST,
        jambo_policyd::actions::ACTION_ACCESS_SECRET,
        b"secrets/root-token",
        1000,
    )
    .expect("Create uncovered req");
    let dec_uncovered = pol_engine
        .evaluate(&policy_cap, &req_uncovered)
        .expect("Evaluate uncovered req");
    assert_eq!(
        dec_uncovered,
        jambo_policyd::AdmissionDecision::Denied {
            reason: "Default Deny: no matching allow rule",
            matching_rule_id: None
        }
    );

    // 31. Traçage Distribué, Propagation de Contexte & Analyse de Latence (Phase 36 - jambo-traced v0.2.34)
    let trace_cap = jambo_traced::TraceCap::new(
        libjambo::Handle::new(2201, 1),
        jambo_traced::trace_rights::ALL,
    );
    let mut collector = jambo_traced::TraceCollector::new();

    let trace_id = [0x55; 16];
    let root_span_id = 100;
    let root_ctx = jambo_traced::TraceContext::new(
        trace_id,
        root_span_id,
        None,
        jambo_traced::trace_flags::FLAG_SAMPLED,
    );

    // Démarrage de la portée racine
    collector
        .start_span(&trace_cap, b"gateway.ingress", &root_ctx, 1000)
        .expect("Start root trace span");

    // Propagation du contexte vers une sous-opération enfant
    let child_span_id = 101;
    let child_ctx = root_ctx.create_child(child_span_id);
    collector
        .start_span(&trace_cap, b"service.resolve", &child_ctx, 1050)
        .expect("Start child trace span");

    // Clôture des portées
    collector
        .finish_span(
            &trace_cap,
            child_span_id,
            jambo_traced::SpanStatus::Ok,
            1150,
        )
        .expect("Finish child trace span");
    collector
        .finish_span(&trace_cap, root_span_id, jambo_traced::SpanStatus::Ok, 1300)
        .expect("Finish root trace span");

    // Vérification de la collecte arborescente
    let mut trace_spans = [jambo_traced::TraceSpan {
        span_id: 0,
        trace_id: [0; 16],
        parent_span_id: None,
        name: [0; jambo_traced::MAX_SPAN_NAME_LEN],
        name_len: 0,
        start_time: 0,
        end_time: 0,
        status: jambo_traced::SpanStatus::Active,
    }; 4];

    let found_spans = collector
        .query_by_trace(&trace_cap, &trace_id, &mut trace_spans)
        .expect("Query trace tree");
    assert_eq!(found_spans, 2);

    // Contrôle d'accès sans autorité ambiante
    let unauth_trace_cap = trace_cap
        .attenuate(jambo_traced::trace_rights::TRACE_QUERY)
        .expect("Attenuate trace cap");
    assert_eq!(
        collector.start_span(&unauth_trace_cap, b"unauth", &root_ctx, 1400),
        Err(libjambo::SysError::PermissionDenied)
    );

    // 32. Infrastructure à Clés Publiques Éphémères & Certificats de Grappe (Phase 37 - jambo-certd v0.2.35)
    let cert_cap = jambo_certd::CertCap::new(
        libjambo::Handle::new(2301, 1),
        jambo_certd::cert_rights::ALL,
    );
    let mut ca = jambo_certd::ClusterCa::new(1, [0xCC; 32], [0x77; 32]);

    let node_pubkey = [0xDD; 32];
    let cert1 = ca
        .issue_cert(
            &cert_cap,
            b"mesh.node-1.cluster",
            node_pubkey,
            1000,
            2000,
            jambo_certd::key_usages::USAGE_SERVER_AUTH
                | jambo_certd::key_usages::USAGE_MESH_ROUTING,
        )
        .expect("Issue ephemeral cert 1");

    assert_eq!(ca.active_count(), 1);

    // Validation du certificat
    let valid_status = ca
        .verify_cert(
            &cert_cap,
            &cert1,
            jambo_certd::key_usages::USAGE_MESH_ROUTING,
            1500,
        )
        .expect("Verify valid cert");
    assert_eq!(valid_status, jambo_certd::CertStatus::Valid);

    // Rejet pour inadéquation d'usage
    let mismatch_status = ca
        .verify_cert(
            &cert_cap,
            &cert1,
            jambo_certd::key_usages::USAGE_CODE_SIGN,
            1500,
        )
        .expect("Verify usage mismatch");
    assert_eq!(mismatch_status, jambo_certd::CertStatus::UsageMismatch);

    // Révocation d'un second certificat
    let cert2 = ca
        .issue_cert(
            &cert_cap,
            b"guest.worker.cluster",
            [0xEE; 32],
            1000,
            2000,
            jambo_certd::key_usages::USAGE_CLIENT_AUTH,
        )
        .expect("Issue ephemeral cert 2");
    ca.revoke_cert(&cert_cap, cert2.serial)
        .expect("Revoke cert 2");
    let revoked_status = ca
        .verify_cert(
            &cert_cap,
            &cert2,
            jambo_certd::key_usages::USAGE_CLIENT_AUTH,
            1500,
        )
        .expect("Verify revoked cert");
    assert_eq!(revoked_status, jambo_certd::CertStatus::Revoked);

    // Contrôle d'accès sans autorité ambiante
    let unauth_cert_cap = cert_cap
        .attenuate(jambo_certd::cert_rights::CERT_VERIFY)
        .expect("Attenuate cert cap");
    assert_eq!(
        ca.issue_cert(
            &unauth_cert_cap,
            b"unauth",
            [0; 32],
            1000,
            2000,
            jambo_certd::key_usages::USAGE_CLIENT_AUTH
        ),
        Err(libjambo::SysError::PermissionDenied)
    );

    // Boucle de supervision de la santé des services Ring 3
    loop {
        unsafe {
            libjambo::syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
        }
    }
}
