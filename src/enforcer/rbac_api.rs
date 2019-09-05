use crate::effect::Effector;
use crate::enforcer::Enforcer;
use crate::persist::Adapter;
use crate::rbac::RoleManager;
use std::collections::HashMap;

impl<A: Adapter, RM: RoleManager + Send + 'static, E: Effector> Enforcer<A, RM, E> {
    /// Get the list of roles for `user`.
    pub fn get_roles_for_user(&self, user: &str, domain: Option<&str>) -> Vec<String> {
        self.role_manager.lock().unwrap().get_roles(user, domain)
    }

    /// Get the list users that have the speficied `role`.
    pub fn get_users_for_role(&self, role: &str, domain: Option<&str>) -> Vec<String> {
        self.role_manager.lock().unwrap().get_users(role, domain)
    }

    /// Returns true if `user` has the specified `role`.
    pub fn has_role_for_user(&self, user: &str, role: &str, domain: Option<&str>) -> bool {
        let roles = self.get_roles_for_user(user, domain);
        roles.iter().any(|r| r == role)
    }

    /// Add a `role` for a `user`.
    pub fn add_role_for_user(&mut self, user: &str, role: &str) -> bool {
        let policy = [user, role];
        self.add_grouping_policy(&policy)
    }

    /// Delete a `role` for a `user`.
    pub fn delete_role_for_user(&mut self, user: &str, role: &str) -> bool {
        let policy = [user, role];
        self.remove_grouping_policy(&policy)
    }

    /// Delete a `Role`
    pub fn delete_role(&mut self, role: &str){
        let users = self.get_users_for_role(role, None);
        for user in users{
            self.delete_role_for_user(&user, role);
        }

        self.remove_policy(&[role]);
    }

    /// Delete a User
    ///
    /// Returns false if user does not exist
    pub fn delete_user(&mut self, user: &str) -> bool{
        return self.delete_roles_for_user(user);
    }

    /// Delete all `roles` for a `user`
    ///
    /// Returns false if user does not have any roles.
    pub fn delete_roles_for_user(&mut self, user: &str) -> bool{
        let roles = self.get_roles_for_user(user, None);

        if roles.len() == 0{
            return false;
        }

        for role in roles{
            self.delete_role_for_user(user, &role);
        }
        return true;
    }

    /// Adds a permission for a `user` or `role`.
    ///
    /// Returns false if the user or role already has the permission.
    pub fn add_permission_for_user(&mut self, user: &str, permission: &[&str]) -> bool{
        let mut params = vec![user];
        params.extend(permission);
        self.add_policy(&params)
    }

    pub fn get_permissions_for_user(&self, user: &str) -> Vec<Vec<String>> {
        return self.get_filtered_policy(0, &[user]);
    }

    //TODO (jtrepanier) Assuming we are checking for one permission
    pub fn has_permission_for_user(&self, user: &str, permission: &[&str]) -> bool{
        return self.has_policy(&vec![user, permission[0]]);
    }

    pub fn delete_permission(&mut self, permission: Vec<&str>) -> bool{
        return self.remove_filtered_policy(1, &permission);
    }

    //TODO (jtrepanier) Assuming we are deleting only one permission
    pub fn delete_permission_for_user(&mut self, user: &str, permission: &[&str]) -> bool{
        let mut params = vec![user];
        params.extend(permission);
        return self.remove_policy(&params);
    }

    pub fn delete_permissions_for_user(&mut self, user: &[&str]) -> bool{
        return self.remove_filtered_policy(0, user)
    }

    /// Gets implicit roles that a user has.
    /// Compared to get_roles_for_user(), this function retrieves indirect roles besides direct roles.
    /// For example:
    /// g, alice, role:admin
    /// g, role:admin, role:user
    ///
    /// get_roles_for_user("alice") can only get: ["role:admin"].
    /// but get_implicit_roles_for_user("alice") will get: ["role:admin", "role:user"].
    pub fn get_implicit_roles_for_user(&self, name: &str) -> Vec<String>{
        let mut res: Vec<String> = Vec::new();
        let mut role_set: HashMap<String, bool> = HashMap::new();
        role_set.insert(name.to_string(), true);

        let mut q: Vec<String> = Vec::new();
        q.push(name.to_string());

        while q.len() > 0 {
            let name = q[0].clone();
            q = q.clone()[1 ..].to_vec();

            let roles:Vec<String> = self.get_roles_for_user(&name, None).clone();
            for i in 0..roles.len(){
                match role_set.get(&roles[i]){
                    Some(_r) => (),
                    None => {
                        res.push(roles[i].clone());
                        q.push(roles[i].clone());
                        role_set.insert(roles[i].clone(), true);
                    }
                }
            }
        }
        return res;
    }

    pub fn get_implicit_permissions_for_user(&self, name: &str) -> Vec<Vec<String>>{
        let mut roles = self.get_implicit_roles_for_user(name);
        roles.insert(0, name.to_string());

        let mut result: Vec<Vec<String>> = Vec::new();

        for role in roles{
            let mut permission = self.get_permissions_for_user(&role);
            permission.retain(|v| !v.is_empty());
            result.extend(permission.clone());
        }

        return result;
    }
}

#[cfg(test)]
mod tests {
    use crate::enforcer::DefaultEnforcer;
    use crate::util::{set_equals, array_2_d_equals};
    use crate::model::Model;
    use crate::persist::file_adapter::FileAdapter;
    use crate::util::array_equals;

    #[test]
    fn test_role_api(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_policy.csv", false);

        let mut enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(set_equals(enforcer.get_roles_for_user("alice", None), vec!["data2_admin".to_owned()]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("bob", None), vec![]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("data2_admin", None), vec![]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("non_exist", None), vec![]), true);

        assert_eq!(enforcer.has_role_for_user("alice", "data1_admin", None), false);
        assert_eq!(enforcer.has_role_for_user("alice", "data2_admin", None), true);

        enforcer.add_role_for_user("alice", "data1_admin");

        assert_eq!(set_equals(enforcer.get_roles_for_user("alice", None), vec!["data2_admin".to_owned(), "data1_admin".to_owned()]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("bob", None), vec![]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("data2_admin", None), vec![]), true);

        enforcer.delete_role_for_user("alice", "data1_admin");

        assert_eq!(set_equals(enforcer.get_roles_for_user("alice", None), vec!["data2_admin".to_owned()]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("bob", None), vec![]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("data2_admin", None), vec![]), true);

        enforcer.delete_roles_for_user("alice");

        assert_eq!(set_equals(enforcer.get_roles_for_user("alice", None), vec![]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("bob", None), vec![]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("data2_admin", None), vec![]), true);

        enforcer.add_role_for_user("alice", "data1_admin");
        enforcer.delete_user("alice");

        assert_eq!(set_equals(enforcer.get_roles_for_user("alice", None), vec![]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("bob", None), vec![]), true);
        assert_eq!(set_equals(enforcer.get_roles_for_user("data2_admin", None), vec![]), true);

        enforcer.add_role_for_user("alice", "data2_admin");

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);

        enforcer.delete_role("data2_admin");

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);
    }

    #[test]
    fn test_permission_api(){
        let model = Model::from_file("examples/basic_without_resources_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/basic_without_resources_policy.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce_without_users("alice",  "read" ).unwrap(), true);
        assert_eq!(enforcer.enforce_without_users("alice", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "write").unwrap(), true);

        assert_eq!(array_2_d_equals(&enforcer.get_permissions_for_user("alice"), &vec![vec!["alice".to_owned(), "read".to_owned()]]), true);
        assert_eq!(array_2_d_equals(&enforcer.get_permissions_for_user("bob"), &vec![vec!["bob".to_owned(), "write".to_owned()]]), true);

        assert_eq!(enforcer.has_permission_for_user("alice", &vec!["read"]), true);
        assert_eq!(enforcer.has_permission_for_user("alice", &vec!["write"]), false);
        assert_eq!(enforcer.has_permission_for_user("bob", &vec!["read"]), false);
        assert_eq!(enforcer.has_permission_for_user("bob", &vec!["write"]), true);

        enforcer.delete_permission(vec!["read"]);

        assert_eq!(enforcer.enforce_without_users("alice",  "read" ).unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("alice", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "write").unwrap(), true);

        enforcer.add_permission_for_user("bob", &vec!["read"]);

        assert_eq!(enforcer.enforce_without_users("alice",  "read" ).unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("alice", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "read").unwrap(), true);
        assert_eq!(enforcer.enforce_without_users("bob", "write").unwrap(), true);


        enforcer.delete_permission_for_user("bob", &vec!["read"]);

        assert_eq!(enforcer.enforce_without_users("alice",  "read" ).unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("alice", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "write").unwrap(), true);

        enforcer.delete_permissions_for_user(&vec!["bob"] );

        assert_eq!(enforcer.enforce_without_users("alice",  "read" ).unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("alice", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "write").unwrap(), false);
    }

    #[test]
    fn test_implicit_role_api(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_with_hierarchy_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(array_2_d_equals(&enforcer.get_permissions_for_user("alice"), &vec![vec!["alice".to_owned(), "data1".to_owned(), "read".to_owned()]]), true);
        assert_eq!(array_2_d_equals(&enforcer.get_permissions_for_user("bob"), &vec![vec!["bob".to_owned(), "data2".to_owned(), "write".to_owned()]]), true);

        assert_eq!(array_equals(&enforcer.get_implicit_roles_for_user("alice"), &vec!["admin".to_string(), "data1_admin".to_string(), "data2_admin".to_string()]), true);
        assert_eq!(array_equals(&enforcer.get_implicit_roles_for_user("bob"), &vec![]), true);
    }

    #[test]
    fn test_implicit_permission_api(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_with_hierarchy_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(array_2_d_equals(&enforcer.get_permissions_for_user("alice"), &vec![vec!["alice".to_owned(), "data1".to_owned(), "read".to_owned()]]), true);
        assert_eq!(array_2_d_equals(&enforcer.get_permissions_for_user("bob"), &vec![vec!["bob".to_owned(), "data2".to_owned(), "write".to_owned()]]), true);

        assert_eq!(array_2_d_equals(&enforcer.get_implicit_permissions_for_user("alice"),
                                    &vec![
                                        vec!["alice".to_string(), "data1".to_string(), "read".to_string()],
                                        vec!["data1_admin".to_string(), "data1".to_string(), "read".to_string()],
                                        vec!["data1_admin".to_string(), "data1".to_string(), "write".to_string()],
                                        vec!["data2_admin".to_string(), "data2".to_string(), "read".to_string()],
                                        vec!["data2_admin".to_string(), "data2".to_string(), "write".to_string()]
                                    ]), true);

        assert_eq!(array_2_d_equals(&enforcer.get_implicit_permissions_for_user("bob"), &vec![vec!["bob".to_string(), "data2".to_string(), "write".to_string()]]), true);
    }
}
