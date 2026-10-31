//! Kit de développement logiciel officiel de JamboOS (JamboSDK)
//!
//! Fournit les abstractions de haut niveau pour concevoir, compiler et packager
//! des applications natives sécurisées par capacités sur micro-noyau JamboOS.

#![no_std]

use libjambo::{cap_rights, Handle, SysError};

/// Manifeste d'application pour le SDK
#[derive(Debug, Clone, Copy)]
pub struct AppManifest {
    pub app_id: &'static str,
    pub name: &'static str,
    pub version: (u16, u16, u16),
    pub requested_rights: u32,
}

/// Contexte d'exécution sécurisé fourni par le SDK à chaque application
pub struct AppContext {
    pub app_id: &'static str,
    pub main_channel: Handle,
    pub primary_vmo: Handle,
}

impl AppContext {
    pub const fn new(app_id: &'static str, main_channel: Handle, primary_vmo: Handle) -> Self {
        Self {
            app_id,
            main_channel,
            primary_vmo,
        }
    }

    /// Envoie un message structuré JamboIDL via le canal principal
    pub fn send_ipc_message(&self, msg_id: u32, data: u64) -> Result<(), SysError> {
        if self.main_channel.is_null() {
            return Err(SysError::InvalidHandle);
        }
        let _ = (msg_id, data);
        Ok(())
    }

    /// Reçoit un message structuré JamboIDL simulé via le canal principal
    pub fn receive_ipc_message(&self) -> Result<(u32, u64), SysError> {
        if self.main_channel.is_null() {
            return Err(SysError::InvalidHandle);
        }
        Ok((1, 0x42))
    }
}

/// Trait définissant le cycle de vie d'une application JamboOS
pub trait JamboApp {
    fn manifest(&self) -> AppManifest;
    fn init(&mut self, ctx: &AppContext) -> Result<(), SysError>;
    fn run_step(&mut self) -> Result<bool, SysError>; // Renvoie true pour continuer, false pour quitter
    fn shutdown(&mut self) -> Result<(), SysError> {
        Ok(())
    }
}

/// Exécute le cycle de vie complet d'une application JamboSDK
pub fn run_app<T: JamboApp>(app: &mut T, ctx: &AppContext) -> Result<u32, SysError> {
    app.init(ctx)?;
    let mut step_count = 0;
    while app.run_step()? {
        step_count += 1;
        if step_count > 100 {
            break;
        }
    }
    app.shutdown()?;
    Ok(step_count)
}

/// Application de test exemple fournie dans le SDK
pub struct HelloWorldApp {
    pub initialized: bool,
    pub steps_run: u32,
    pub stopped: bool,
}

impl Default for HelloWorldApp {
    fn default() -> Self {
        Self::new()
    }
}

impl HelloWorldApp {
    pub const fn new() -> Self {
        Self {
            initialized: false,
            steps_run: 0,
            stopped: false,
        }
    }
}

impl JamboApp for HelloWorldApp {
    fn manifest(&self) -> AppManifest {
        AppManifest {
            app_id: "org.jambostack.helloworld",
            name: "Hello World Native",
            version: (1, 0, 0),
            requested_rights: cap_rights::READ | cap_rights::SEND,
        }
    }

    fn init(&mut self, _ctx: &AppContext) -> Result<(), SysError> {
        self.initialized = true;
        Ok(())
    }

    fn run_step(&mut self) -> Result<bool, SysError> {
        self.steps_run += 1;
        Ok(self.steps_run < 3)
    }

    fn shutdown(&mut self) -> Result<(), SysError> {
        self.stopped = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_app_lifecycle() {
        let mut app = HelloWorldApp::new();
        let ctx = AppContext::new("org.jambostack.test", Handle::new(1, 1), Handle::new(2, 1));
        let steps = run_app(&mut app, &ctx).expect("run app");
        assert_eq!(steps, 2);
        assert!(app.initialized);
        assert!(app.stopped);
    }
}
