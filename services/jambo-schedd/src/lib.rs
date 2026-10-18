//! Ordonnanceur de Charges de Travail et de Conteneurs Distribués (`jambo-schedd`)
//!
//! Fournit une orchestration de grappe déterministe `#![no_std]` pour les micro-machines virtuelles,
//! les sandboxes WebAssembly et les processus POSIX de JamboOS sans autorité ambiante.
//! Les opérations de soumission, migration et régulation sont gouvernées par la capacité `SchedCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_TASKS: usize = 32;
pub const MAX_NODES: usize = 8;
pub const MAX_NAME_LEN: usize = 24;

/// Droits de capacité pour l'ordonnanceur distribué.
pub mod sched_rights {
    pub const SCHED_SUBMIT: u32 = 0x01;
    pub const SCHED_CANCEL: u32 = 0x02;
    pub const SCHED_QUERY: u32 = 0x04;
    pub const SCHED_MIGRATE: u32 = 0x08;
    pub const SCHED_DRAIN: u32 = 0x10;
    pub const SCHED_ADMIN: u32 = 0x80;
    pub const ALL: u32 =
        SCHED_SUBMIT | SCHED_CANCEL | SCHED_QUERY | SCHED_MIGRATE | SCHED_DRAIN | SCHED_ADMIN;
}

/// Jeton de capacité pour l'ordonnanceur de grappe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedCap {
    pub handle: Handle,
    pub rights: u32,
}

impl SchedCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }
}

/// Runtimes d'exécution supportés par l'ordonnanceur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeType {
    MicroVmm,
    Wasm,
    Posix,
}

/// États du cycle de vie d'une tâche.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Running,
    Completed,
    Failed,
    Evicted,
}

/// Spécification déclarative d'une tâche à planifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskSpec {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub runtime: RuntimeType,
    pub vcpus: u32,
    pub memory_pages: u32,
    pub preferred_node: Option<u32>,
}

impl TaskSpec {
    pub fn new(
        id: u32,
        name: &[u8],
        runtime: RuntimeType,
        vcpus: u32,
        memory_pages: u32,
        preferred_node: Option<u32>,
    ) -> Self {
        let mut n_buf = [0u8; MAX_NAME_LEN];
        let copy_len = name.len().min(MAX_NAME_LEN);
        n_buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: n_buf,
            name_len: copy_len,
            runtime,
            vcpus,
            memory_pages,
            preferred_node,
        }
    }

    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Instance d'une tâche ordonnancée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Task {
    pub spec: TaskSpec,
    pub assigned_node: Option<u32>,
    pub state: TaskState,
    pub started_at_ms: u64,
}

/// Nœud de calcul au sein de la grappe JamboOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterNode {
    pub id: u32,
    pub total_vcpus: u32,
    pub total_pages: u32,
    pub used_vcpus: u32,
    pub used_pages: u32,
    pub draining: bool,
    pub healthy: bool,
}

impl ClusterNode {
    pub fn new(id: u32, total_vcpus: u32, total_pages: u32) -> Self {
        Self {
            id,
            total_vcpus,
            total_pages,
            used_vcpus: 0,
            used_pages: 0,
            draining: false,
            healthy: true,
        }
    }

    pub fn can_fit(&self, vcpus: u32, pages: u32) -> bool {
        if self.draining || !self.healthy {
            return false;
        }
        self.used_vcpus.saturating_add(vcpus) <= self.total_vcpus
            && self.used_pages.saturating_add(pages) <= self.total_pages
    }

    pub fn allocate(&mut self, vcpus: u32, pages: u32) -> bool {
        if !self.can_fit(vcpus, pages) {
            return false;
        }
        self.used_vcpus += vcpus;
        self.used_pages += pages;
        true
    }

    pub fn release(&mut self, vcpus: u32, pages: u32) {
        self.used_vcpus = self.used_vcpus.saturating_sub(vcpus);
        self.used_pages = self.used_pages.saturating_sub(pages);
    }
}

/// Ordonnanceur distribué multi-nœuds.
pub struct ClusterScheduler {
    pub nodes: [Option<ClusterNode>; MAX_NODES],
    pub tasks: [Option<Task>; MAX_TASKS],
    pub next_task_id: u32,
}

impl Default for ClusterScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterScheduler {
    pub const fn new() -> Self {
        Self {
            nodes: [None; MAX_NODES],
            tasks: [None; MAX_TASKS],
            next_task_id: 1,
        }
    }

    /// Enregistre un nœud de calcul avec ses quotas matériels.
    pub fn register_node(
        &mut self,
        cap: &SchedCap,
        node_id: u32,
        vcpus: u32,
        pages: u32,
    ) -> Result<(), SysError> {
        if !cap.has_right(sched_rights::SCHED_ADMIN) {
            return Err(SysError::PermissionDenied);
        }

        let slot = self.nodes.iter_mut().find(|n| match n {
            Some(existing) => existing.id == node_id,
            None => false,
        });

        if let Some(existing_slot) = slot {
            if let Some(node) = existing_slot {
                node.total_vcpus = vcpus;
                node.total_pages = pages;
                node.healthy = true;
                return Ok(());
            }
        }

        let free_slot = self
            .nodes
            .iter_mut()
            .find(|n| n.is_none())
            .ok_or(SysError::OutOfMemory)?;

        *free_slot = Some(ClusterNode::new(node_id, vcpus, pages));
        Ok(())
    }

    /// Soumet une nouvelle tâche à ordonnancer.
    pub fn submit_task(&mut self, cap: &SchedCap, mut spec: TaskSpec) -> Result<u32, SysError> {
        if !cap.has_right(sched_rights::SCHED_SUBMIT) {
            return Err(SysError::PermissionDenied);
        }

        let id = self.next_task_id;
        self.next_task_id += 1;
        spec.id = id;

        let free_slot = self
            .tasks
            .iter_mut()
            .find(|t| t.is_none())
            .ok_or(SysError::OutOfMemory)?;

        *free_slot = Some(Task {
            spec,
            assigned_node: None,
            state: TaskState::Pending,
            started_at_ms: 0,
        });

        Ok(id)
    }

    /// Boucle de placement des tâches en attente (Least-Allocated Node Score).
    pub fn schedule_pending(&mut self, current_time_ms: u64) -> usize {
        let mut placed_count = 0;

        for t_idx in 0..MAX_TASKS {
            let (vcpus, pages, preferred) = match &self.tasks[t_idx] {
                Some(task) if task.state == TaskState::Pending => (
                    task.spec.vcpus,
                    task.spec.memory_pages,
                    task.spec.preferred_node,
                ),
                _ => continue,
            };

            // Recherche du meilleur nœud éligible
            let mut best_node_idx: Option<usize> = None;
            let mut min_load_score = u32::MAX;

            for n_idx in 0..MAX_NODES {
                if let Some(node) = &self.nodes[n_idx] {
                    if !node.can_fit(vcpus, pages) {
                        continue;
                    }
                    if let Some(pref) = preferred {
                        if node.id == pref {
                            best_node_idx = Some(n_idx);
                            break;
                        }
                    }
                    // Score : charge relative en pourcentage approximatif
                    let load_score = (node.used_vcpus * 100) / node.total_vcpus.max(1)
                        + (node.used_pages * 100) / node.total_pages.max(1);
                    if load_score < min_load_score {
                        min_load_score = load_score;
                        best_node_idx = Some(n_idx);
                    }
                }
            }

            if let Some(n_idx) = best_node_idx {
                let node = self.nodes[n_idx].as_mut().unwrap();
                let node_id = node.id;
                assert!(node.allocate(vcpus, pages));

                let task = self.tasks[t_idx].as_mut().unwrap();
                task.assigned_node = Some(node_id);
                task.state = TaskState::Running;
                task.started_at_ms = current_time_ms;
                placed_count += 1;
            }
        }

        placed_count
    }

    /// Annule ou interrompt une tâche.
    pub fn cancel_task(&mut self, cap: &SchedCap, task_id: u32) -> Result<(), SysError> {
        if !cap.has_right(sched_rights::SCHED_CANCEL) {
            return Err(SysError::PermissionDenied);
        }

        let task = self
            .tasks
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|t| t.spec.id == task_id))
            .ok_or(SysError::InvalidArgument)?;

        if task.state == TaskState::Running {
            if let Some(nid) = task.assigned_node {
                for n in self.nodes.iter_mut() {
                    if let Some(node) = n {
                        if node.id == nid {
                            node.release(task.spec.vcpus, task.spec.memory_pages);
                            break;
                        }
                    }
                }
            }
        }

        task.state = TaskState::Completed;
        task.assigned_node = None;
        Ok(())
    }

    /// Migre une tâche active vers un nœud cible.
    pub fn migrate_task(
        &mut self,
        cap: &SchedCap,
        task_id: u32,
        target_node_id: u32,
    ) -> Result<(), SysError> {
        if !cap.has_right(sched_rights::SCHED_MIGRATE) {
            return Err(SysError::PermissionDenied);
        }

        let (vcpus, pages, current_node_id) = {
            let task = self
                .tasks
                .iter()
                .find_map(|slot| slot.as_ref().filter(|t| t.spec.id == task_id))
                .ok_or(SysError::InvalidArgument)?;
            if task.state != TaskState::Running {
                return Err(SysError::InvalidArgument);
            }
            (
                task.spec.vcpus,
                task.spec.memory_pages,
                task.assigned_node.ok_or(SysError::InvalidArgument)?,
            )
        };

        if current_node_id == target_node_id {
            return Ok(());
        }

        // Vérification de la capacité sur le nœud cible
        let target_node = self
            .nodes
            .iter_mut()
            .find_map(|n| n.as_mut().filter(|node| node.id == target_node_id))
            .ok_or(SysError::InvalidArgument)?;

        if !target_node.allocate(vcpus, pages) {
            return Err(SysError::OutOfMemory);
        }

        // Libération des ressources de l'ancien nœud
        for n in self.nodes.iter_mut() {
            if let Some(node) = n {
                if node.id == current_node_id {
                    node.release(vcpus, pages);
                    break;
                }
            }
        }

        // Mise à jour de la tâche
        let task = self
            .tasks
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|t| t.spec.id == task_id))
            .unwrap();
        task.assigned_node = Some(target_node_id);

        Ok(())
    }

    /// Déclenche le drainage d'un nœud et réordonnance ses tâches.
    pub fn drain_node(&mut self, cap: &SchedCap, node_id: u32) -> Result<usize, SysError> {
        if !cap.has_right(sched_rights::SCHED_DRAIN) {
            return Err(SysError::PermissionDenied);
        }

        let node = self
            .nodes
            .iter_mut()
            .find_map(|n| n.as_mut().filter(|node| node.id == node_id))
            .ok_or(SysError::InvalidArgument)?;
        node.draining = true;

        let mut evicted_count = 0;
        for t in self.tasks.iter_mut() {
            if let Some(task) = t {
                if task.assigned_node == Some(node_id) && task.state == TaskState::Running {
                    node.release(task.spec.vcpus, task.spec.memory_pages);
                    task.assigned_node = None;
                    task.state = TaskState::Pending;
                    evicted_count += 1;
                }
            }
        }

        Ok(evicted_count)
    }

    /// Consulte l'état d'une tâche.
    pub fn query_task(&self, cap: &SchedCap, task_id: u32) -> Result<Task, SysError> {
        if !cap.has_right(sched_rights::SCHED_QUERY) {
            return Err(SysError::PermissionDenied);
        }

        self.tasks
            .iter()
            .find_map(|slot| slot.as_ref().filter(|t| t.spec.id == task_id))
            .copied()
            .ok_or(SysError::InvalidArgument)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_permissions() {
        let mut sched = ClusterScheduler::new();
        let unauth_cap = SchedCap::new(Handle::new(1, 1), 0);
        let submit_cap = SchedCap::new(Handle::new(2, 1), sched_rights::SCHED_SUBMIT);

        let spec = TaskSpec::new(0, b"vmm-workload", RuntimeType::MicroVmm, 2, 64, None);

        // Rejet sans SCHED_SUBMIT
        assert_eq!(
            sched.submit_task(&unauth_cap, spec),
            Err(SysError::PermissionDenied)
        );

        // Succès avec SCHED_SUBMIT
        let tid = sched.submit_task(&submit_cap, spec).unwrap();
        assert_eq!(tid, 1);
    }

    #[test]
    fn test_placement_and_reconciliation() {
        let mut sched = ClusterScheduler::new();
        let admin_cap = SchedCap::new(Handle::new(1, 1), sched_rights::ALL);

        // Enregistrement de deux nœuds
        sched.register_node(&admin_cap, 101, 8, 1024).unwrap();
        sched.register_node(&admin_cap, 102, 8, 1024).unwrap();

        // Soumission de deux tâches
        let t1 = TaskSpec::new(0, b"wasm-compute", RuntimeType::Wasm, 2, 128, None);
        let t2 = TaskSpec::new(0, b"posix-job", RuntimeType::Posix, 4, 256, None);

        sched.submit_task(&admin_cap, t1).unwrap();
        sched.submit_task(&admin_cap, t2).unwrap();

        // Ordonnancement automatique
        let placed = sched.schedule_pending(1000);
        assert_eq!(placed, 2);

        let task1 = sched.query_task(&admin_cap, 1).unwrap();
        let task2 = sched.query_task(&admin_cap, 2).unwrap();
        assert_eq!(task1.state, TaskState::Running);
        assert_eq!(task2.state, TaskState::Running);
        assert!(task1.assigned_node.is_some());
        assert!(task2.assigned_node.is_some());
    }

    #[test]
    fn test_drain_and_migration() {
        let mut sched = ClusterScheduler::new();
        let admin_cap = SchedCap::new(Handle::new(1, 1), sched_rights::ALL);

        sched.register_node(&admin_cap, 201, 4, 512).unwrap();
        sched.register_node(&admin_cap, 202, 4, 512).unwrap();

        let t = TaskSpec::new(0, b"vmm-instance", RuntimeType::MicroVmm, 2, 128, Some(201));
        let tid = sched.submit_task(&admin_cap, t).unwrap();
        sched.schedule_pending(500);

        let task = sched.query_task(&admin_cap, tid).unwrap();
        assert_eq!(task.assigned_node, Some(201));

        // Migration manuelle vers 202
        sched.migrate_task(&admin_cap, tid, 202).unwrap();
        let task_migrated = sched.query_task(&admin_cap, tid).unwrap();
        assert_eq!(task_migrated.assigned_node, Some(202));

        // Drain de 202 -> la tâche redevient Pending et est réaffectée à 201
        let evicted = sched.drain_node(&admin_cap, 202).unwrap();
        assert_eq!(evicted, 1);

        let task_pending = sched.query_task(&admin_cap, tid).unwrap();
        assert_eq!(task_pending.state, TaskState::Pending);

        sched.schedule_pending(600);
        let task_rescheduled = sched.query_task(&admin_cap, tid).unwrap();
        assert_eq!(task_rescheduled.assigned_node, Some(201));
    }
}
