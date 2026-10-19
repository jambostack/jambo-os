//! Module de test et validation du Compositeur Graphique Ring 3 & JamboUI (Phase 46 - v0.2.44)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_comp::{DamageRect, JamboComp};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_ui::{AccessibilityRole, AccessibilityTree, Button, CheckBox, Color, JamboTerm, Label};

/// Exécute la suite de tests du compositeur graphique jambo-comp et de JamboUI (Phase 46)
pub fn execute_graphics_compositor_test() -> bool {
    kprintln!(
        "[COMP/TEST] Démarrage du test du compositeur graphique jambo-comp & JamboUI (Phase 46)..."
    );

    // 1. Initialisation de JamboComp (1920x1080 @ 60 Hz)
    let mut comp = JamboComp::new(1920, 1080, 60);
    assert_eq!(comp.screen_width, 1920);
    assert_eq!(comp.screen_height, 1080);
    assert_eq!(comp.refresh_rate_hz, 60);
    kprintln!("[COMP/INIT] Compositeur VirtIO-GPU initialisé (1920x1080 @ 60 Hz)");

    // 2. Création de surfaces clientes avec isolation stricte par capacités
    let cap1 = match comp.create_surface(10, 800, 600) {
        Ok(h) => h,
        Err(_) => {
            kprintln!("[COMP/ERR] Échec de création de surface cliente #1");
            return false;
        }
    };
    let cap2 = match comp.create_surface(20, 1024, 768) {
        Ok(h) => h,
        Err(_) => {
            kprintln!("[COMP/ERR] Échec de création de surface cliente #2");
            return false;
        }
    };

    assert!(comp.verify_surface_isolation(10, cap1));
    assert!(!comp.verify_surface_isolation(10, cap2));
    assert!(comp.verify_surface_isolation(20, cap2));
    assert!(!comp.verify_surface_isolation(20, cap1));
    kprintln!("[COMP/ISOLATION] Confinement des surfaces validé : aucun client ne peut accéder aux pixels d'un tiers");

    // 3. Hit-testing, Z-index et déplacement de fenêtres
    assert!(comp.window_at(130, 130).is_some());
    assert!(comp.bring_to_front(1).is_ok());
    assert!(comp.move_window(cap1, 50, 50).is_ok());
    kprintln!("[COMP/WM] Gestionnaire de fenêtres (Hit-testing, Z-ordering, Déplacement) validé");

    // 4. Damage Tracking et composition sélective vers VirtIO-GPU
    let damage = DamageRect::new(10, 10, 200, 150);
    assert!(comp.damage_surface(cap1, damage).is_ok());
    let damaged_regions = match comp.composite_frame() {
        Ok(count) => count,
        Err(_) => {
            kprintln!("[COMP/ERR] Échec de la composition de trame");
            return false;
        }
    };
    assert!(damaged_regions > 0);
    assert_eq!(comp.total_frames_composed, 1);
    kprintln!("[COMP/VSYNC] Composition sélective Damage Tracking & Scanout Flush validés");

    // 5. Portail de capture d'écran sans autorité ambiante
    assert_eq!(
        comp.request_screen_capture(10, None),
        Err(SysError::PermissionDenied)
    );
    assert_eq!(
        comp.request_screen_capture(10, Some(Handle::new(10, 1))),
        Err(SysError::PermissionDenied)
    );
    let valid_portal_cap = Handle::new(150, 1);
    let capture_rect = comp
        .request_screen_capture(10, Some(valid_portal_cap))
        .expect("Portail de capture accordé");
    assert_eq!(capture_rect.width, 1920);
    assert_eq!(capture_rect.height, 1080);
    kprintln!(
        "[COMP/PORTAL] Portail de capture sécurisé validé (Rejet strict sans jeton PortalCap)"
    );

    // 6. Validation du Framework JamboUI et de l'arbre d'accessibilité obligatoire
    let btn = Button::new(1, "Enregistrer", 140, 45);
    let lbl = Label::new(2, "Statut Système : Nominal");
    let mut chk = CheckBox::new(3, "Accélération Matérielle", false);
    chk.toggle();
    assert!(chk.checked);

    let mut a11y_tree = AccessibilityTree::new();
    assert!(a11y_tree.register(btn.accessibility).is_ok());
    assert!(a11y_tree.register(lbl.accessibility).is_ok());
    assert!(a11y_tree.register(chk.accessibility).is_ok());
    assert_eq!(a11y_tree.count(), 3);

    assert!(a11y_tree.find_by_role(AccessibilityRole::Button).is_some());
    assert!(a11y_tree.find_by_role(AccessibilityRole::Label).is_some());
    assert!(a11y_tree
        .find_by_role(AccessibilityRole::CheckBox)
        .is_some());
    kprintln!("[JAMBOUI/A11Y] Composants déclaratifs & Arbre d'accessibilité 100% conformes");

    // 7. Validation du Terminal graphique interactif JamboTerm
    let mut term = JamboTerm::new();
    term.write_str("JamboTerm v0.2.44 ready\n");
    assert_eq!(term.cursor_row, 1);
    assert_eq!(term.cursor_col, 0);
    assert_eq!(term.grid[0][0], 'J');
    kprintln!("[JAMBOUI/TERM] Terminal graphique JamboTerm opérationnel");

    // 8. Validation des commandes graphiques dans JamboShell
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'gui status'
    let (st_status, len_status) = shell.execute_line("gui status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap_or("");
    assert!(str_status.contains("1920x1080") && str_status.contains("Damage Tracking"));
    kprintln!("[COMP/SHELL] Commande 'gui status' validée");

    // Commande 'gui demo'
    let (st_demo, len_demo) = shell.execute_line("gui demo", &mut out_buf);
    assert_eq!(st_demo, ShellStatus::Success);
    let str_demo = core::str::from_utf8(&out_buf[..len_demo]).unwrap_or("");
    assert!(
        str_demo.contains("Surface graphique créée") && str_demo.contains("Trame VSync recomposée")
    );
    kprintln!("[COMP/SHELL] Commande 'gui demo' validée");

    // Commande 'gui capture'
    let (st_cap, len_cap) = shell.execute_line("gui capture", &mut out_buf);
    assert_eq!(st_cap, ShellStatus::Success);
    let str_cap = core::str::from_utf8(&out_buf[..len_cap]).unwrap_or("");
    assert!(
        str_cap.contains("Capture d'écran non autorisée rejetée") && str_cap.contains("PortalCap")
    );
    kprintln!("[COMP/SHELL] Commande 'gui capture' validée");

    kprintln!(
        "[COMP/PASS] Compositeur graphique jambo-comp et framework JamboUI validés avec succès."
    );
    true
}
