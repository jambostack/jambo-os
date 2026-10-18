extern crate alloc;
use super::thread::Thread;
use crate::mm::{load_elf64, AddressSpace};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use jambo_abi::{auxv, SysError};
use spin::Mutex;

static NEXT_PID: AtomicU64 = AtomicU64::new(10);

/// Alloue un identifiant de processus unique
pub fn allocate_pid() -> u64 {
    NEXT_PID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Active,
    Terminated(i32),
}

pub struct Process {
    pub id: u64,
    pub name: String,
    pub aspace: Arc<AddressSpace>,
    pub threads: Mutex<Vec<Arc<Mutex<Thread>>>>,
    pub state: Mutex<ProcessState>,
    pub entry_point: u64,
    pub user_stack_top: u64,
}

impl Process {
    pub fn new(id: u64, name: &str, aspace: Arc<AddressSpace>) -> Arc<Self> {
        Arc::new(Self {
            id,
            name: String::from(name),
            aspace,
            threads: Mutex::new(Vec::new()),
            state: Mutex::new(ProcessState::Active),
            entry_point: 0,
            user_stack_top: 0,
        })
    }

    /// Prépare le cadre initial de pile utilisateur conformément à la System V AMD64 ABI
    /// Layout : [argc][argv...][0][envp...][0][auxv...][AT_NULL, 0][strings]
    pub fn setup_user_stack(
        &self,
        stack_top: u64,
        args: &[&str],
        envs: &[&str],
        auxv_entries: &[(u64, u64)],
    ) -> Result<u64, SysError> {
        let mut sp = stack_top;

        // 1. Écrire les 16 octets aléatoires pour AT_RANDOM
        sp -= 16;
        let random_bytes = [
            0x42, 0x13, 0x37, 0x73, 0x5a, 0x9b, 0x10, 0xef, 0xfe, 0xca, 0x00, 0x42, 0x11, 0x22,
            0x33, 0x44,
        ];
        self.aspace.write_bytes(sp as usize, &random_bytes)?;
        let random_ptr = sp;

        // 2. Écrire les chaînes d'environnement (terminées par '\0')
        let mut env_ptrs = Vec::with_capacity(envs.len());
        for env in envs.iter().rev() {
            let bytes = env.as_bytes();
            sp -= (bytes.len() + 1) as u64;
            self.aspace.write_bytes(sp as usize, bytes)?;
            self.aspace
                .write_bytes((sp + bytes.len() as u64) as usize, &[0])?;
            env_ptrs.push(sp);
        }
        env_ptrs.reverse();

        // 3. Écrire les chaînes d'arguments (terminées par '\0')
        let mut arg_ptrs = Vec::with_capacity(args.len());
        for arg in args.iter().rev() {
            let bytes = arg.as_bytes();
            sp -= (bytes.len() + 1) as u64;
            self.aspace.write_bytes(sp as usize, bytes)?;
            self.aspace
                .write_bytes((sp + bytes.len() as u64) as usize, &[0])?;
            arg_ptrs.push(sp);
        }
        arg_ptrs.reverse();

        // 4. Aligner sp sur 8 octets
        sp &= !0x7;

        // 5. Calculer le nombre total de mots de 64 bits dans la table :
        // argc (1) + argv (args.len()) + 1 (NULL) + envp (envs.len()) + 1 (NULL) + (auxv.len() + 2) * 2
        let auxv_count = auxv_entries.len() + 2; // + AT_RANDOM + AT_NULL
        let total_words = 1 + args.len() + 1 + envs.len() + 1 + auxv_count * 2;
        let final_table_bytes = (total_words * 8) as u64;

        // 6. Aligner pour garantir qu'à l'entrée (_start), rsp % 16 == 0
        if ((sp - final_table_bytes) % 16) != 0 {
            sp -= 8;
            self.aspace.write_bytes(sp as usize, &0u64.to_ne_bytes())?;
        }

        // 7. Construire la table de pointeurs et vecteurs auxiliaires
        let mut table: Vec<u64> = Vec::with_capacity(total_words);

        // argc
        table.push(args.len() as u64);

        // argv pointers
        for &arg_ptr in &arg_ptrs {
            table.push(arg_ptr);
        }
        table.push(0); // Terminateur NULL argv

        // envp pointers
        for &env_ptr in &env_ptrs {
            table.push(env_ptr);
        }
        table.push(0); // Terminateur NULL envp

        // Auxiliary Vector (auxv)
        table.push(auxv::AT_RANDOM);
        table.push(random_ptr);

        for &(key, val) in auxv_entries {
            table.push(key);
            table.push(val);
        }

        table.push(auxv::AT_NULL);
        table.push(0);

        // 8. Écrire la table sur la pile
        sp -= final_table_bytes;

        for (i, &word) in table.iter().enumerate() {
            let word_addr = sp + (i * core::mem::size_of::<u64>()) as u64;
            self.aspace
                .write_bytes(word_addr as usize, &word.to_ne_bytes())?;
        }

        debug_assert_eq!(
            sp % 16,
            0,
            "Le pointeur de pile utilisateur doit être aligné sur 16 octets"
        );

        Ok(sp)
    }

    /// Charge un exécutable ELF64, initialise l'espace d'adressage et configure le thread utilisateur initial
    pub fn create_user_process(
        id: u64,
        name: &str,
        elf_bytes: &[u8],
        args: &[&str],
        envs: &[&str],
    ) -> Result<(Arc<Self>, Arc<Mutex<Thread>>), SysError> {
        let aspace = Arc::new(AddressSpace::new().ok_or(SysError::OutOfMemory)?);
        let elf_info = load_elf64(&aspace, elf_bytes)?;

        let process = Arc::new(Self {
            id,
            name: String::from(name),
            aspace: aspace.clone(),
            threads: Mutex::new(Vec::new()),
            state: Mutex::new(ProcessState::Active),
            entry_point: elf_info.entry_point,
            user_stack_top: elf_info.stack_pointer,
        });

        // Configurer les vecteurs auxiliaires System V ABI
        let auxv_entries = [
            (auxv::AT_PAGESZ, crate::mm::PAGE_SIZE as u64),
            (auxv::AT_ENTRY, elf_info.entry_point),
            (auxv::AT_PHDR, elf_info.phdr_vaddr),
            (auxv::AT_PHENT, elf_info.phentsize as u64),
            (auxv::AT_PHNUM, elf_info.phnum as u64),
        ];

        let user_sp =
            process.setup_user_stack(elf_info.stack_pointer, args, envs, &auxv_entries)?;

        let thread_id = id * 1000 + 1;
        let thread = Thread::new_user(thread_id, id, aspace.clone(), elf_info.entry_point, user_sp)
            .ok_or(SysError::OutOfMemory)?;

        process.threads.lock().push(thread.clone());

        Ok((process, thread))
    }
}
