use std::collections::HashMap;
use std::fs;
use std::path::Path;

use lazy_static::lazy_static;

use crate::assertion::Assertion;
use crate::config::Config;
use crate::error::Error;
use crate::util::{escape_assertion, remove_comments};

mod function;
pub mod policy;

pub use crate::model::function::{get_function_map, FunctionMap};

type AssertionMap = HashMap<String, Assertion>;

#[derive(Debug)]
pub struct Model {
    pub data: HashMap<String, AssertionMap>,
}

lazy_static! {
    static ref SECTION_NAME_MAP: HashMap<&'static str, &'static str> = {
        let mut map = HashMap::new();
        map.insert("r", "request_definition");
        map.insert("p", "policy_definition");
        map.insert("g", "role_definition");
        map.insert("e", "policy_effect");
        map.insert("m", "matchers");
        map
    };
}

fn get_section_name(name: &str) -> &str {
    SECTION_NAME_MAP.get(name).unwrap()
}

fn get_section_value(sec: &str, i: i32) -> String {
    if i == 1 {
        sec.to_string()
    } else {
        format!("{}{}", sec, i)
    }
}

fn shorthand_section_name(name: &str) -> Option<&str> {
    match name {
        "request_definition" => Some("r"),
        "policy_definition" => Some("p"),
        "role_definition" => Some("g"),
        "policy_effect" => Some("e"),
        "matchers" => Some("m"),
        _ => None,
    }
}

impl Model {
    /// Create an empty Model instance.
    pub fn new() -> Self {
        Model { data: HashMap::new() }
    }

    /// Create a Model instance from a file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let text = fs::read_to_string(path)?;
        Model::from_string(&text)
    }

    /// Create a Model instance from a string.
    pub fn from_string(text: &str) -> Result<Self, Error> {
        let mut model = Model::new();
        let cfg = Config::from_string(text)?;

        model.load_section(&cfg, "request_definition")?;
        model.load_section(&cfg, "policy_definition")?;
        model.load_section(&cfg, "policy_effect")?;
        model.load_section(&cfg, "matchers")?;
        model.load_section(&cfg, "role_definition")?;

        Ok(model)
    }

    fn load_assertion(&mut self, cfg: &Config, sec: &str, key: &str) -> Result<bool, Error> {
        if let Some(value) = cfg.string(key, Some(sec)) {
            self.add_def(shorthand_section_name(sec).unwrap(), key, value.as_str())
        } else {
            Ok(false)
        }
    }

    pub(crate) fn add_def(&mut self, sec: &str, key: &str, value: &str) -> Result<bool, Error> {
        let mut assertion = Assertion::new();

        if value == "" {
            return Ok(false);
        }

        assertion.key = key.to_string();
        assertion.value = value.to_string();

        if sec == "r" || sec == "p" {
            assertion.tokens = assertion.value.split(", ").map(|v| format!("{}_{}", key, v)).collect();
        } else {
            assertion.value = escape_assertion(remove_comments(assertion.value.as_str())).to_string();
        }

        if !self.data.contains_key(sec) {
            let sec_map: HashMap<String, Assertion> = HashMap::new();
            self.data.insert(sec.to_string(), sec_map);
        }

        let sec_map = self.data.get_mut(sec).unwrap();
        sec_map.insert(key.to_string(), assertion);

        Ok(true)
    }

    fn load_section(&mut self, cfg: &Config, section: &str) -> Result<(), Error> {
        let mut i = 1;
        while self
            .load_assertion(
                cfg,
                section,
                get_section_value(shorthand_section_name(section).unwrap(), i).as_str(),
            )
            .unwrap()
        {
            i += 1;
        }
        Ok(())
    }

    pub fn print_model(&self) -> Result<(), Error> {
        unimplemented!()
    }

    /// Load a policy rule from a line of text.
    pub fn load_policy_line(&mut self, line: &str) -> Result<(), Error> {
        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }

        let tokens: Vec<&str> = line.split(',').map(|t| t.trim()).collect();

        if tokens.len() < 2 {
            return Err(Error::InvalidValue);
        }

        let key = tokens[0];
        let section = &key[0..1];

        if !self.data.contains_key(section) {
            self.data.insert(String::from(section), AssertionMap::new());
        }

        let assertion_map = self.data.get_mut(section).unwrap();

        if !assertion_map.contains_key(key) {
            assertion_map.insert(key.to_string(), Assertion::new());
        }

        let assertion = assertion_map.get_mut(key).unwrap();
        let mut value = vec![];

        for s in &tokens[1..] {
            value.push(String::from(*s));
        }

        assertion.policy.push(value);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::model::Model;
    use crate::persist::file_adapter::FileAdapter;
    use crate::enforcer::DefaultEnforcer;
    use crate::util::builtin_operators;
    use crate::rbac::MatchingFunction;
    

    #[test]
    fn test_basic_model(){
        let model = Model::from_file("examples/basic_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/basic_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

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
    fn test_basic_model_no_policy(){
        let model = Model::from_file("examples/basic_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/empty.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), false);
    }

    #[test]
    fn test_basic_model_with_root(){
        let model = Model::from_file("examples/basic_with_root_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/basic_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("root", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("root", "data1", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("root", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("root", "data2", "write").unwrap(), true);
    }

    #[test]
    #[ignore]
    /// TODO: Need to modify enforce function to return true if r_sub == root
    fn test_basic_model_with_root_no_policy(){
        let model = Model::from_file("examples/basic_with_root_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/empty.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("root", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("root", "data1", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("root", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("root", "data2", "write").unwrap(), true);
    }

    #[test]
    fn test_basic_model_without_users(){
        let model = Model::from_file("examples/basic_without_users_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/basic_without_users_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce_without_users("data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce_without_users("data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("data2", "write").unwrap(), true);
    }

    #[test]
    fn test_basic_model_without_resources(){
        let model = Model::from_file("examples/basic_without_resources_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/basic_without_resources_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce_without_users("alice", "read").unwrap(), true);
        assert_eq!(enforcer.enforce_without_users("alice", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_without_users("bob", "write").unwrap(), true);
    }

    #[test]
    fn test_rbac_model(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

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
    fn test_rbac_model_with_resources_roles(){
        let model = Model::from_file("examples/rbac_with_resource_roles_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_with_resource_roles_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);
    }

    #[test]
    fn test_rbac_model_with_domains(){
        let model = Model::from_file("examples/rbac_with_domains_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_with_domains_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "write").unwrap(), true);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "write").unwrap(), true);
    }

    #[test]
    fn test_rbac_model_with_domains_at_runtime(){
        let model = Model::from_file("examples/rbac_with_domains_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/empty.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        enforcer.add_policy(&["admin", "domain1", "data1", "read"]);
        enforcer.add_policy(&["admin", "domain1", "data1", "write"]);
        enforcer.add_policy(&["admin", "domain2", "data2", "read"]);
        enforcer.add_policy(&["admin", "domain2", "data2", "write"]);

        enforcer.add_grouping_policy(&["alice", "admin", "domain1"]);
        enforcer.add_grouping_policy(&["bob", "admin", "domain2"]);

        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "write").unwrap(), true);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "write").unwrap(), true);

        enforcer.remove_filtered_policy(1, &["domain1", "data1"]);

        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "write").unwrap(), true);

        enforcer.remove_policy(&["admin", "domain2", "data2", "read"]);

        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "write").unwrap(), true);
    }

    #[test]
    fn test_rbac_model_with_domains_at_runtime_mock_adapter(){
        let model = Model::from_file("examples/rbac_with_domains_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_with_domains_policy.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        enforcer.add_policy(&["admin", "domain3", "data1", "read"]);
        enforcer.add_grouping_policy(&["alice", "admin", "domain3"]);

        assert_eq!(enforcer.enforce_with_domain("alice", "domain3", "data1", "read").unwrap(), true);

        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "read").unwrap(), true);
        enforcer.remove_filtered_policy(1, &["domain1", "data1"]);
        assert_eq!(enforcer.enforce_with_domain("alice", "domain1", "data1", "read").unwrap(), false);

        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "read").unwrap(), true);
        enforcer.remove_policy(&["admin", "domain2", "data2", "read"]);
        assert_eq!(enforcer.enforce_with_domain("bob", "domain2", "data2", "read").unwrap(), false);
    }

    #[test]
    #[ignore]
    fn test_rbac_model_with_deny(){
        let model = Model::from_file("examples/rbac_with_deny_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_with_deny_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);
    }

    #[test]
    #[ignore]
    fn test_rbac_model_with_only_deny(){
        let model = Model::from_file("examples/rbac_with_not_deny_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_with_deny_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), false);
    }

    #[test]
    fn test_rbac_model_with_custom_data(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_policy.csv", false);
        let mut enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        // You can add custom data to a grouping policy. Casbin will ignore it. It is only meaningful to the caller.
        // This feature can be used to store information like wether "bob" is an end user (so no subject will inherit "bob")
        // For Casbin, it is equivalent to: enforcer.add_grouping_policy("bob", "data2_admin")
        enforcer.add_grouping_policy(&["bob", "data2_admin", "custom_data"]);

        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data2", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "data1", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data1", "write").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);

        // You should also take the custom data as a parameter when deleting a grouping policy.
        // enforcer.remove_grouping_policy("bob", "data2_admin") won't work.
        // Or you can remove it by using remove_filtered_grouping_policy().
        enforcer.remove_grouping_policy(&["bob", "data2_admin", "custom_data"]);

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
    fn test_rbac_model_with_pattern(){
        let model = Model::from_file("examples/rbac_with_pattern_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_with_pattern_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        enforcer.add_matching_function("keyMatch2", MatchingFunction(Box::new(builtin_operators::key_match2)));

        assert_eq!(enforcer.enforce("alice", "/book/1", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/book/2", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/pen/1", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/pen/2", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/book/1", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/book/2", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/pen/1", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "/pen/2", "GET").unwrap(), true);

        //enforcer.add_matching_function("keyMatch3", MatchingFunction(Box::new(builtin_operators::key_match3)));

        assert_eq!(enforcer.enforce("alice", "/book2/1", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/book2/2", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/pen2/1", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/pen2/2", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/book2/1", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/book2/2", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "/pen2/1", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "/pen2/2", "GET").unwrap(), true);
    }

    #[test]
    #[ignore]
    /// TODO(jtrepanier): Add missing function to allow switching role manager
    fn test_rbac_model_with_custom_role_manager(){
        let model = Model::from_file("examples/rbac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/rbac_policy.csv", false);
        let _enforcer = DefaultEnforcer::new(model, adapter).unwrap();
    }

    #[test]
    #[ignore]
    fn test_abac_model(){
        let model = Model::from_file("examples/abac_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/empty.csv", false);
        let _enforcer = DefaultEnforcer::new(model, adapter).unwrap();
    }

    #[test]
    fn test_key_match_model(){
        let model = Model::from_file("examples/keymatch_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/keymatch_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce("alice", "/alice_data/resource1", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/alice_data/resource1", "POST").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/alice_data/resource2", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/alice_data/resource2", "POST").unwrap(), false);
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
    fn test_key_match_2_model(){
        let model = Model::from_file("examples/keymatch2_model.conf").unwrap();
        let adapter = FileAdapter::new("examples/keymatch2_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).unwrap();

        assert_eq!(enforcer.enforce("alice", "/alice_data", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "/alice_data/resource1", "GET").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "/alice_data2/myid", "GET").unwrap(), false);
        assert_eq!(enforcer.enforce("alice", "/alice_data2/myid/using/res-id", "GET").unwrap(), true);
    }

    #[test]
    #[ignore]
    /// TODO: Allow adding a keymatch function to functionmap
    fn test_key_match_custom_model(){

    }
}
