use std::fmt;
use std::sync::{Arc, Mutex};

use crate::error::Error;

mod default_role_manager;

pub use crate::rbac::default_role_manager::DefaultRoleManager;

pub type Function = dyn Fn(&str, &str) -> bool + Sync + Send;

pub struct MatchingFunction(pub Box<Function>);

impl fmt::Debug for MatchingFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MatchingFunction")
    }
}

pub trait RoleManager {
    fn clear(&mut self) -> Result<(), Error>;
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error>;
    fn delete_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error>;
    fn has_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> bool;
    fn get_roles(&self, name: &str, domain: Option<&str>) -> Vec<String>;
    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String>;
    fn print_roles(&self) -> Result<(), Error>;
    fn add_matching_function(&mut self, name: &str, matching_func: MatchingFunction);
}

#[derive(Clone, Debug)]
pub struct Role {
    pub name: String,
    roles: Vec<Arc<Mutex<Role>>>,
}

impl Role {
    pub fn new(name: &str) -> Self {
        Role {
            name: name.to_string(),
            roles: Vec::new(),
        }
    }

    fn roles_contains(&self, name: &str) -> bool {
        for role in &self.roles {
            if role.lock().unwrap().name == name {
                return true;
            }
        }

        false
    }

    pub fn add_role(&mut self, role: Arc<Mutex<Role>>) {
        let name = role.lock().unwrap().to_string();
        if !self.roles_contains(&name) {
            self.roles.push(role);
        }
    }

    pub fn delete_role(&mut self, role: Arc<Mutex<Role>>) {
        let name = role.lock().unwrap().name.to_string();
        let index = self.roles.iter().position(|x| x.lock().unwrap().name == name);
        if let Some(index) = index {
            self.roles.remove(index);
        }
    }

    pub fn has_role(&self, name: &str, hierarchy_level: i32) -> bool {
        if self.name == name {
            return true;
        }

        if hierarchy_level <= 0 {
            return false;
        }

        for role in &self.roles {
            if role.lock().unwrap().has_role(name, hierarchy_level - 1) {
                return true;
            }
        }

        false
    }

    pub fn has_direct_role(&self, name: &str) -> bool {
        for role in &self.roles {
            if name == role.lock().unwrap().name {
                return true;
            }
        }

        false
    }

    pub fn get_roles(&self) -> Vec<String> {
        let mut roles = Vec::new();
        for role in &self.roles {
            roles.push(role.lock().unwrap().name.clone());
        }
        roles
    }
}

impl PartialEq for Role {
    fn eq(&self, other: &Role) -> bool {
        self.name == other.name
    }
}

impl fmt::Display for Role {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.name.as_ref())?;
        fmt.write_str(" < ")?;
        let roles = self.get_roles();
        fmt.write_str(&roles.join(","))?;
        Ok(())
    }
}
