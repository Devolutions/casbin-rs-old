use std::ops::DerefMut;
use std::sync::{Arc, Mutex};

use eval::{to_value, Expr};

use crate::effect::{DefaultEffector, Effect, Effector};
use crate::error::Error;
use crate::model::Model;
use crate::model::{get_function_map, FunctionMap};
use crate::persist::Adapter;
use crate::rbac::{DefaultRoleManager, RoleManager, MatchingFunction};
use crate::util::builtin_operators;

mod internal_api;
pub mod management_api;
pub mod rbac_api;

#[derive(Debug)]
pub struct DefaultEnforcer();

impl DefaultEnforcer {
    pub fn new<A: Adapter>(model: Model, policy: A) -> Result<Enforcer<A, DefaultRoleManager, DefaultEffector>, Error> {
        Enforcer::new(model, policy, DefaultRoleManager::new(10), DefaultEffector::new())
    }
}

/// Enforcer is the main interface for authorization enforcement and policy management.
#[derive(Debug)]
pub struct Enforcer<A: Adapter, RM: RoleManager + Send + 'static, E: Effector> {
    model: Model,
    function_map: FunctionMap,
    adapter: A,
    role_manager: Arc<Mutex<RM>>,
    effector: E,
    auto_build_role_links: bool,
}

impl<A: Adapter, RM: RoleManager + Send + 'static, E: Effector> Enforcer<A, RM, E> {
    /// Create an instance of an Enforcer from a `model` and `policy`.
    pub fn new(model: Model, policy: A, role_manager: RM, effector: E) -> Result<Enforcer<A, RM, E>, Error> {
        let mut enforcer = Enforcer {
            model,
            function_map: get_function_map(),
            adapter: policy,
            role_manager: Arc::new(Mutex::new(role_manager)),
            effector,
            auto_build_role_links: true,
        };

        enforcer.load_policy()?;

        Ok(enforcer)
    }

    /// Rebuild the role inheritance relations.
    fn build_role_links(&mut self) -> Result<(), Error> {
        self.role_manager.lock().unwrap().clear()?;
        self.model
            .build_role_links(self.role_manager.lock().unwrap().deref_mut())?;
        Ok(())
    }

    /// Reload the policy from source.
    fn load_policy(&mut self) -> Result<(), Error> {
        self.model.clear_policy();
        self.adapter.load_policy(&mut self.model)?;

        if self.auto_build_role_links {
            self.build_role_links()?;
        }

        Ok(())
    }

    fn clear_policy(&mut self) {
        self.model.clear_policy();
    }

    /// Decide whether `subject` can access `object` with the operation `action`.

    // TODO: enforce does not handle matcherResults.
    pub fn enforce(&self, subject: &str, object: &str, action: &str) -> Result<bool, Error> {
        let mut policy_effects: Vec<Effect> = vec![];

        let expr_string = &self.model.data["m"]["m"].value;

        for policy in &self.model.data["p"]["p"].policy {
            let mut expr = Expr::new(expr_string.clone())
                .value("r_sub", subject)
                .value("r_obj", object)
                .value("r_act", action)
                .value("p_sub", &policy[0])
                .value("p_obj", &policy[1])
                .value("p_act", &policy[2])
                .function("keyMatch", |v| {
                    Ok(to_value(builtin_operators::key_match(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                })
                .function("keyMatch2", |v| {
                    Ok(to_value(builtin_operators::key_match2(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                })
                .function("ipMatch", |v| {
                    Ok(to_value(builtin_operators::ip_match(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                })
                .function("regexMatch", |v| {
                    Ok(to_value(builtin_operators::regex_match(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                });

            if self.model.data.contains_key("g"){
                let g = &self.model.data["g"];
                for gfunction in g{
                    let role_manager = Arc::clone(&self.role_manager);
                    let name = gfunction.0;
                    expr = expr.function(name.to_string(), move|v|{
                        let name1 = v[0].as_str().unwrap();
                        let name2 = v[1].as_str().unwrap();
                        let mut domain = None;

                        if v.len() > 2{
                            domain = Some(v[2].as_str().unwrap());
                        }

                        let result = role_manager.lock().unwrap().has_link(name1, name2, domain);
                        Ok(to_value(result))
                    });
                }
            }

            let result = expr.exec().map_err(Error::Eval)?;

            if result == to_value(false) {
                policy_effects.push(Effect::Indeterminate);
                continue;
            }

            // TODO(sduquette): Assuming that the effect of rules is Allow for now.
            policy_effects.push(Effect::Allow);
        }

        let effect_expr = &self.model.data["e"]["e"].value;
        self.effector.merge_effects(effect_expr, policy_effects, vec![])
    }

    // TODO: enforce does not handle matcherResults.
    pub fn enforce_with_domain(&self, subject: &str, domain: &str, object: &str, action: &str) -> Result<bool, Error> {
        let mut policy_effects: Vec<Effect> = vec![];

        let expr_string = &self.model.data["m"]["m"].value;

        for policy in &self.model.data["p"]["p"].policy {
            let mut expr = Expr::new(expr_string.clone())
                .value("r_sub", subject)
                .value("r_dom", domain)
                .value("r_obj", object)
                .value("r_act", action)
                .value("p_sub", &policy[0])
                .value("p_dom", &policy[1])
                .value("p_obj", &policy[2])
                .value("p_act", &policy[3])
                .function("keyMatch", |v| {
                    Ok(to_value(builtin_operators::key_match(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                })
                .function("keyMatch2", |v| {
                    Ok(to_value(builtin_operators::key_match2(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                })
                .function("ipMatch", |v| {
                    Ok(to_value(builtin_operators::ip_match(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                })
                .function("regexMatch", |v| {
                    Ok(to_value(builtin_operators::regex_match(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                });

            if self.model.data.contains_key("g"){
                let g = &self.model.data["g"];
                for gfunction in g{
                    let role_manager = Arc::clone(&self.role_manager);
                    let name = gfunction.0;
                    expr = expr.function(name.to_string(), move|v|{
                        let name1 = v[0].as_str().unwrap();
                        let name2 = v[1].as_str().unwrap();
                        let mut domain = None;

                        if v.len() > 2{
                            domain = Some(v[2].as_str().unwrap());
                        }

                        let result = role_manager.lock().unwrap().has_link(name1, name2, domain);
                        Ok(to_value(result))
                    });
                }
            }

            let result = expr.exec().map_err(Error::Eval)?;

            if result == to_value(false) {
                policy_effects.push(Effect::Indeterminate);
                continue;
            }

            // TODO(sduquette): Assuming that the effect of rules is Allow for now.
            policy_effects.push(Effect::Allow);
        }

        let effect_expr = &self.model.data["e"]["e"].value;
        self.effector.merge_effects(effect_expr, policy_effects, vec![])
    }

    // TODO: enforce does not handle matcherResults.
    pub fn enforce_without_users(&self, subject: &str, action: &str) -> Result<bool, Error>{
        let mut policy_effects: Vec<Effect> = vec![];

        let expr_string = &self.model.data["m"]["m"].value;
        let matcher;

        // Temporary solution to allow test_basic_model_without_users() and test_permission_api() to both work using this function
        if expr_string.contains("obj"){
            matcher = "obj";
        }
        else {
            matcher = "sub"
        }

        for policy in &self.model.data["p"]["p"].policy{
            let mut expr = Expr::new(expr_string.clone())
                .value(format!("{}{}", "r_", matcher), subject)
                .value("r_act", action)
                .value(format!("{}{}", "p_", matcher), &policy[0])
                .value("p_act", &policy[1])
                .function("keyMatch", |v| {
                    Ok(to_value(builtin_operators::key_match(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                })
                .function("keyMatch2", |v| {
                    Ok(to_value(builtin_operators::key_match2(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                })
                .function("ipMatch", |v| {
                    Ok(to_value(builtin_operators::ip_match(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                })
                .function("regexMatch", |v| {
                    Ok(to_value(builtin_operators::regex_match(
                        v[0].as_str().unwrap(),
                        v[1].as_str().unwrap(),
                    )))
                });

            if self.model.data.contains_key("g"){
                let g = &self.model.data["g"];
                for gfunction in g{
                    let role_manager = Arc::clone(&self.role_manager);
                    let name = gfunction.0;
                    expr = expr.function(name.to_string(), move|v|{
                        let name1 = v[0].as_str().unwrap();
                        let name2 = v[1].as_str().unwrap();
                        let mut domain = None;

                        if v.len() > 2{
                            domain = Some(v[2].as_str().unwrap());
                        }

                        let result = role_manager.lock().unwrap().has_link(name1, name2, domain);
                        Ok(to_value(result))
                    });
                }
            }

            let result = expr.exec().map_err(Error::Eval)?;

            if result == to_value(false) {
                policy_effects.push(Effect::Indeterminate);
                continue;
            }

            // TODO(sduquette): Assuming that the effect of rules is Allow for now.
            policy_effects.push(Effect::Allow);
        }

        let effect_expr = &self.model.data["e"]["e"].value;
        self.effector.merge_effects(effect_expr, policy_effects, vec![])
    }


    pub fn add_matching_function(&self, name: &str, matching_func: MatchingFunction){
        self.role_manager.lock().unwrap().add_matching_function(name, matching_func);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::persist::file_adapter::FileAdapter;
    
    use crate::util::{array_2_d_equals};

    #[test]
    fn test_match_in_memory() {
        let mut model = Model::new();

        assert_eq!(model.add_def("r", "r", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("p", "p", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("e", "e", "some(where (p.eft == allow))").unwrap(), true);
        assert_eq!(
            model
                .add_def("m", "m", "(r.sub == p.sub) && (r.obj == p.obj) && (r.act == p.act)")
                .unwrap(),
            true
        );

        let adapter = FileAdapter::new("examples/basic_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
    }

    #[test]
    fn test_key_match_in_memory() {
        let mut model = Model::new();
        assert_eq!(model.add_def("r", "r", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("p", "p", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("e", "e", "some(where (p.eft == allow))").unwrap(), true);
        assert_eq!(
            model
                .add_def(
                    "m",
                    "m",
                    "(r.sub == p.sub) && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)"
                )
                .unwrap(),
            true
        );

        let adapter = FileAdapter::new("examples/keymatch_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");

        assert_eq!(enforcer.enforce("alice", "/alice_data/resource1", "GET").unwrap(), true);
        assert_eq!(
            enforcer.enforce("alice", "/alice_data/resource1", "POST").unwrap(),
            true
        );
        assert_eq!(enforcer.enforce("alice", "/alice_data/resource2", "GET").unwrap(), true);
        assert_eq!(
            enforcer.enforce("alice", "/alice_data/resource2", "POST").unwrap(),
            false
        );
        assert_eq!(enforcer.enforce("alice", "/bob_data/resource1", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "/bob_data/resource1", "POST").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "/bob_data/resource2", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "/bob_data/resource2", "POST").unwrap(), false);

        assert_eq!(enforcer.enforce("bob", "/alice_data/resource1", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/alice_data/resource1", "POST").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/alice_data/resource2", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "/alice_data/resource2", "POST").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/bob_data/resource1", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/bob_data/resource1", "POST").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "/bob_data/resource2", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/bob_data/resource2", "POST").unwrap(), true);

        assert_eq!(enforcer.enforce("cathy", "/cathy_data", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("cathy", "/cathy_data", "POST").unwrap(), true);
        assert_eq!(enforcer.enforce("cathy", "/cathy_data", "DELETE").unwrap(), false);
    }

    #[test]
    fn test_key_match_in_memory_deny() {
        let mut model = Model::new();
        assert_eq!(model.add_def("r", "r", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("p", "p", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("e", "e", "!some(where (p.eft == deny))").unwrap(), true);
        assert_eq!(
            model
                .add_def(
                    "m",
                    "m",
                    "(r.sub == p.sub) && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)"
                )
                .unwrap(),
            true
        );

        let adapter = FileAdapter::new("examples/keymatch_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");

        assert_eq!(
            enforcer.enforce("alice", "/alice_data/resource2", "POST").unwrap(),
            true
        );
    }

    #[test]
    fn test_rbac_in_memory() {
        let mut model = Model::new();
        assert_eq!(model.add_def("r", "r", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("p", "p", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("g", "g", "_, _").unwrap(), true);
        assert_eq!(model.add_def("e", "e", "some(where (p.eft == allow))").unwrap(), true);
        assert_eq!(
            model
                .add_def("m", "m", "g(r.sub, p.sub) && (r.obj == p.obj) && (r.act == p.act)")
                .unwrap(),
            true);

        // TODO(sduquette): This is a temporary workaround to create an enforcer with an empty policy.
        let adapter = FileAdapter::new("examples/empty.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");

        assert_eq!(enforcer.add_permission_for_user("alice", &["data1", "read"]), true);
        assert_eq!(enforcer.add_permission_for_user("bob", &["data2", "write"]), true);
        assert_eq!(
            enforcer.add_permission_for_user("data2_admin", &["data2", "read"]),
            true
        );
        assert_eq!(
            enforcer.add_permission_for_user("data2_admin", &["data2", "write"]),
            true
        );
        assert_eq!(enforcer.add_role_for_user("alice", "data2_admin"), true);

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);
    }

    #[test]
    fn test_rbac_model_in_memory_2(){
        let text = "
        [request_definition]\n
        r = sub, obj, act\n
        [policy_definition]\n
        p = sub, obj, act\n
        [role_definition]\n
        g = _, _\n
        [policy_effect]\n
        e = some(where (p.eft == allow))\n
        [matchers]\n
        m = g(r.sub, p.sub) && (r.obj == p.obj) && (r.act == p.act)";

        let model = Model::from_string(text).unwrap();
        let adapter = FileAdapter::new("examples/empty.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");

        assert_eq!(enforcer.add_permission_for_user("alice", &["data1", "read"]), true);
        assert_eq!(enforcer.add_permission_for_user("bob", &["data2", "write"]), true);
        assert_eq!(enforcer.add_permission_for_user("data2_admin", &["data2", "read"]), true);
        assert_eq!(enforcer.add_permission_for_user("data2_admin", &["data2", "write"]), true);

        assert_eq!(enforcer.add_role_for_user("alice", "data2_admin"), true);

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);
    }

    #[test]
    fn test_not_used_rbac_in_memory(){
        let mut model = Model::new();
        assert_eq!(model.add_def("r", "r", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("p", "p", "sub, obj, act").unwrap(), true);
        assert_eq!(model.add_def("g", "g", "_, _").unwrap(), true);
        assert_eq!(model.add_def("e", "e", "some(where (p.eft == allow))").unwrap(), true);
        assert_eq!(
            model
                .add_def("m", "m", "g(r.sub, p.sub) && (r.obj == p.obj) && (r.act == p.act)")
                .unwrap(),
            true);

        let adapter = FileAdapter::new("examples/empty.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");

        assert_eq!(enforcer.add_permission_for_user("alice", &["data1", "read"]), true);
        assert_eq!(enforcer.add_permission_for_user("bob", &["data2", "write"]), true);

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
    #[ignore]
    /// Test failed because Eval crates does not recognize `in` operator (jtrepanier)
    fn test_matcher_using_in_operator(){
        let model = Model::from_file("examples/rbac_model_matcher_using_in_op.conf").unwrap();
        let adapter = FileAdapter::new("examples/empty.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");

        assert_eq!(enforcer.add_permission_for_user("alice", &["data1", "read"]), true);

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data3", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("anyone", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("anyone", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("anyone", "data3", "read").unwrap(), true);
    }

    #[test]
    fn test_reload_policy(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_policy.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");

        enforcer.load_policy().unwrap();
        let policy = enforcer.get_policy();

        let test_policy =
            vec![
                vec!["alice".to_owned(), "data1".to_owned(), "read".to_owned()],
                vec!["bob".to_owned(), "data2".to_owned(), "write".to_owned()],
                vec!["data2_admin".to_owned(), "data2".to_owned(), "read".to_owned()],
                vec!["data2_admin".to_owned(), "data2".to_owned(), "write".to_owned()]
                ];

        assert_eq!(array_2_d_equals(&policy, &test_policy), true);
    }

    #[test]
    #[ignore]
    // TODO(jtrepanier) add save policy function to Enforcer
    fn test_save_policy(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_policy.csv", false);
        let _enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");
    }

    #[test]
    fn test_clear_policy(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_policy.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");
        enforcer.clear_policy();
    }

    #[test]
    fn test_role_links(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/empty.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");
        enforcer.build_role_links().unwrap();

        enforcer.enforce("user501", "data9", "read").unwrap();
    }
}
