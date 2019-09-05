use std::collections::HashMap;
use std::sync::{Arc, Mutex};


use crate::error::Error;
use crate::rbac::{Role, RoleManager, MatchingFunction};

#[derive(Debug)]
pub struct DefaultRoleManager {
    roles: HashMap<String, Arc<Mutex<Role>>>,
    max_hierarchy_level: i32,
    has_pattern: bool,
    matching_function: Option<MatchingFunction>
}

impl RoleManager for DefaultRoleManager {
    /// Clear all stored data and reset the role manager to the initial state.
    fn clear(&mut self) -> Result<(), Error> {
        self.roles.clear();
        Ok(())
    }

    /// Add a link such that `name1` inherits the role `name2`.
    ///
    /// `domain` is a prefix to the roles.
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error> {
        let (name1, name2) = DefaultRoleManager::get_names_with_domain(name1, name2, domain);

        let role1 = self.create_role(&name1);
        let role2 = self.create_role(&name2);

        role1.lock().unwrap().add_role(role2);

        Ok(())
    }

    /// Delete the inheritance link between `name1` and  `name2`.
    ///
    /// `domain` is a prefix to the roles.
    fn delete_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error> {
        let (name1, name2) = DefaultRoleManager::get_names_with_domain(name1, name2, domain);

        let role1 = self.get_role(&name1).ok_or(Error::MissingRole(name1.clone()))?;
        let role2 = self.get_role(&name2).ok_or(Error::MissingRole(name2.clone()))?;

        role1.lock().unwrap().delete_role(role2);
        Ok(())
    }

    /// Return true if `name1` inherits the role `name2`.
    fn has_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> bool {
        let (name1, name2) = DefaultRoleManager::get_names_with_domain(name1, name2, domain);

        if name1 == name2 {
            return true;
        }

        if !self.has_role(&name1) || !self.has_role(&name2){
            return false;
        }

        let role1 = self.create_role(&name1);
        let result = role1.lock().unwrap().has_role(&name2, self.max_hierarchy_level);
        result
    }

    /// Get the list of roles that `name` inherits.
    ///
    /// `domain` is a prefix to the role.
    fn get_roles(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let name = DefaultRoleManager::get_name_with_domain(name, domain);
        if let Some(role) = self.get_role(&name) {
            role.lock().unwrap().get_roles()
        } else {
            Vec::new()
        }
    }

    /// Get the list of users that inherit `name`.
    ///
    /// `domain` is a prefix to the role.
    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let name = DefaultRoleManager::get_name_with_domain(name, domain);

        if !self.has_role(&name) {
            return Vec::new();
        }

        let mut names = vec![];

        for (role_name, role) in &self.roles {
            if role.lock().unwrap().has_direct_role(&name) {
                names.push(role_name.clone())
            }
        }

        names
    }

    fn print_roles(&self) -> Result<(), Error> {
        unimplemented!()
    }

    fn add_matching_function(&mut self, _name: &str, matching_func: MatchingFunction){
        self.has_pattern = true;
        self.matching_function = Some(matching_func);
    }
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: i32) -> Self {
        DefaultRoleManager {
            roles: HashMap::new(),
            max_hierarchy_level,
            has_pattern: false,
            matching_function: None
        }
    }

    fn has_role(&self, name: &str) -> bool {
        if self.has_pattern {
            if let Some(func) = &self.matching_function {
                let f = &func.0;
                for role in &self.roles {
                    let key = role.0;
                    if f(name, key) {
                        return true;
                    }
                }
            }
        }
        self.roles.contains_key(name)
    }

    fn create_role(&mut self, name: &str) -> Arc<Mutex<Role>> {
        let mut name = name;
        if self.has_pattern {
            if let Some(func) = &self.matching_function {
                let f = &func.0;
                for role in &self.roles {
                    let key = &role.0;
                    if f(name, key) {
                        name = key;
                        break;
                    }
                }
            }
        }

        if self.roles.contains_key(name){
            Arc::clone(self.roles.get(name).unwrap())
        } else {
            let role = Arc::new(Mutex::new(Role::new(name)));
            &self.roles.insert(name.to_string(), Arc::clone(&role));
            role
        }
    }

    fn get_role(&self, name: &str) -> Option<Arc<Mutex<Role>>> {
        Some(Arc::clone(self.roles.get(name)?))
    }

    fn get_name_with_domain(name: &str, domain: Option<&str>) -> String {
        match domain {
            Some(domain) => domain.to_string() + "::" + name,
            None => name.to_string(),
        }
    }

    fn get_names_with_domain(name1: &str, name2: &str, domain: Option<&str>) -> (String, String) {
        match domain {
            Some(domain) => (domain.to_string() + "::" + name1, domain.to_string() + "::" + name2),
            None => (name1.to_string(), name2.to_string()),
        }
    }

    fn add_matching_function(&mut self, _name: &str, matching_func: MatchingFunction){
        self.has_pattern = true;
        self.matching_function = Some(matching_func);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role() {
        let mut manager = DefaultRoleManager::new(3);
        manager.add_link("u1", "g1", None).unwrap();
        manager.add_link("u2", "g1", None).unwrap();
        manager.add_link("u3", "g2", None).unwrap();
        manager.add_link("u4", "g2", None).unwrap();
        manager.add_link("u4", "g3", None).unwrap();
        manager.add_link("g1", "g3", None).unwrap();

        // Current role inheritance tree:
        //             g3    g2
        //            /  \  /  \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        assert_eq!(manager.has_link("u1", "g1", None), true);
        assert_eq!(manager.has_link("u1", "g2", None), false);
        assert_eq!(manager.has_link("u1", "g3", None), true);
        assert_eq!(manager.has_link("u2", "g1", None), true);
        assert_eq!(manager.has_link("u2", "g2", None), false);
        assert_eq!(manager.has_link("u2", "g3", None), true);
        assert_eq!(manager.has_link("u3", "g1", None), false);
        assert_eq!(manager.has_link("u3", "g2", None), true);
        assert_eq!(manager.has_link("u3", "g3", None), false);
        assert_eq!(manager.has_link("u4", "g1", None), false);
        assert_eq!(manager.has_link("u4", "g2", None), true);
        assert_eq!(manager.has_link("u4", "g3", None), true);

        assert_eq!(manager.get_roles("u1", None), ["g1"]);
        assert_eq!(manager.get_roles("u2", None), ["g1"]);
        assert_eq!(manager.get_roles("u3", None), ["g2"]);
        assert_eq!(manager.get_roles("u4", None), ["g2", "g3"]);
        assert_eq!(manager.get_roles("g1", None), ["g3"]);
        assert_eq!(manager.get_roles("g2", None), Vec::<String>::new());
        assert_eq!(manager.get_roles("g3", None), Vec::<String>::new());

        manager.delete_link("g1", "g3", None).unwrap();
        manager.delete_link("u4", "g2", None).unwrap();

        // Current role inheritance tree after deleting the links:
        //             g3    g2
        //               \     \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        assert_eq!(manager.has_link("u1", "g1", None), true);
        assert_eq!(manager.has_link("u1", "g2", None), false);
        assert_eq!(manager.has_link("u1", "g3", None), false);
        assert_eq!(manager.has_link("u2", "g1", None), true);
        assert_eq!(manager.has_link("u2", "g2", None), false);
        assert_eq!(manager.has_link("u2", "g3", None), false);
        assert_eq!(manager.has_link("u3", "g1", None), false);
        assert_eq!(manager.has_link("u3", "g2", None), true);
        assert_eq!(manager.has_link("u3", "g3", None), false);
        assert_eq!(manager.has_link("u4", "g1", None), false);
        assert_eq!(manager.has_link("u4", "g2", None), false);
        assert_eq!(manager.has_link("u4", "g3", None), true);

        assert_eq!(manager.get_roles("u1", None), ["g1"]);
        assert_eq!(manager.get_roles("u2", None), ["g1"]);
        assert_eq!(manager.get_roles("u3", None), ["g2"]);
        assert_eq!(manager.get_roles("u4", None), ["g3"]);
        assert_eq!(manager.get_roles("g1", None), Vec::<String>::new());
        assert_eq!(manager.get_roles("g2", None), Vec::<String>::new());
        assert_eq!(manager.get_roles("g3", None), Vec::<String>::new());
    }

    #[test]
    fn test_domain_role() {
        let mut manager = DefaultRoleManager::new(3);
        manager.add_link("u1", "g1", Some("domain1")).unwrap();
        manager.add_link("u2", "g1", Some("domain1")).unwrap();
        manager.add_link("u3", "admin", Some("domain2")).unwrap();
        manager.add_link("u4", "admin", Some("domain2")).unwrap();
        manager.add_link("u4", "admin", Some("domain1")).unwrap();
        manager.add_link("g1", "admin", Some("domain1")).unwrap();

        // Current role inheritance tree:
        //       domain1:admin    domain2:admin
        //            /       \  /       \
        //      domain1:g1     u4         u3
        //         /  \
        //       u1    u2

        assert_eq!(manager.has_link("u1", "g1", Some("domain1")), true);
        assert_eq!(manager.has_link("u1", "g1", Some("domain2")), false);
        assert_eq!(manager.has_link("u1", "admin", Some("domain1")), true);
        assert_eq!(manager.has_link("u1", "admin", Some("domain2")), false);

        assert_eq!(manager.has_link("u2", "g1", Some("domain1")), true);
        assert_eq!(manager.has_link("u2", "g1", Some("domain2")), false);
        assert_eq!(manager.has_link("u2", "admin", Some("domain1")), true);
        assert_eq!(manager.has_link("u2", "admin", Some("domain2")), false);

        assert_eq!(manager.has_link("u3", "g1", Some("domain1")), false);
        assert_eq!(manager.has_link("u3", "g1", Some("domain2")), false);
        assert_eq!(manager.has_link("u3", "admin", Some("domain1")), false);
        assert_eq!(manager.has_link("u3", "admin", Some("domain2")), true);

        assert_eq!(manager.has_link("u4", "g1", Some("domain1")), false);
        assert_eq!(manager.has_link("u4", "g1", Some("domain2")), false);
        assert_eq!(manager.has_link("u4", "admin", Some("domain1")), true);
        assert_eq!(manager.has_link("u4", "admin", Some("domain2")), true);

        manager.delete_link("g1", "admin", Some("domain1")).unwrap();
        manager.delete_link("u4", "admin", Some("domain2")).unwrap();

        // Current role inheritance tree after deleting the links:
        //       domain1:admin    domain2:admin
        //                    \          \
        //      domain1:g1     u4         u3
        //         /  \
        //       u1    u2

        assert_eq!(manager.has_link("u1", "g1", Some("domain1")), true);
        assert_eq!(manager.has_link("u1", "g1", Some("domain2")), false);
        assert_eq!(manager.has_link("u1", "admin", Some("domain1")), false);
        assert_eq!(manager.has_link("u1", "admin", Some("domain2")), false);

        assert_eq!(manager.has_link("u2", "g1", Some("domain1")), true);
        assert_eq!(manager.has_link("u2", "g1", Some("domain2")), false);
        assert_eq!(manager.has_link("u2", "admin", Some("domain1")), false);
        assert_eq!(manager.has_link("u2", "admin", Some("domain2")), false);

        assert_eq!(manager.has_link("u3", "g1", Some("domain1")), false);
        assert_eq!(manager.has_link("u3", "g1", Some("domain2")), false);
        assert_eq!(manager.has_link("u3", "admin", Some("domain1")), false);
        assert_eq!(manager.has_link("u3", "admin", Some("domain2")), true);

        assert_eq!(manager.has_link("u4", "g1", Some("domain1")), false);
        assert_eq!(manager.has_link("u4", "g1", Some("domain2")), false);
        assert_eq!(manager.has_link("u4", "admin", Some("domain1")), true);
        assert_eq!(manager.has_link("u4", "admin", Some("domain2")), false);
    }

    #[test]
    fn test_clear() {
        let mut manager = DefaultRoleManager::new(3);
        manager.add_link("u1", "g1", None).unwrap();
        manager.add_link("u2", "g1", None).unwrap();
        manager.add_link("u3", "g2", None).unwrap();
        manager.add_link("u4", "g2", None).unwrap();
        manager.add_link("u4", "g3", None).unwrap();
        manager.add_link("g1", "g3", None).unwrap();

        // Current role inheritance tree:
        //             g3    g2
        //            /  \  /  \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        manager.clear().unwrap();

        assert_eq!(manager.has_link("u1", "g1", None), false);
        assert_eq!(manager.has_link("u1", "g2", None), false);
        assert_eq!(manager.has_link("u1", "g3", None), false);
        assert_eq!(manager.has_link("u2", "g1", None), false);
        assert_eq!(manager.has_link("u2", "g2", None), false);
        assert_eq!(manager.has_link("u2", "g3", None), false);
        assert_eq!(manager.has_link("u3", "g1", None), false);
        assert_eq!(manager.has_link("u3", "g2", None), false);
        assert_eq!(manager.has_link("u3", "g3", None), false);
        assert_eq!(manager.has_link("u4", "g1", None), false);
        assert_eq!(manager.has_link("u4", "g2", None), false);
        assert_eq!(manager.has_link("u4", "g3", None), false);
    }
}
