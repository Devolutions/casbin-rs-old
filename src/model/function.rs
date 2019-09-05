use std::collections::HashMap;
use std::fmt;

use crate::util::builtin_operators;

pub type Function = dyn Fn(&str, &str) -> bool + Sync + Send;

pub struct FunctionMap(pub HashMap<&'static str, Box<Function>>);

impl fmt::Debug for FunctionMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FunctionMap")
    }
}

pub fn get_function_map() -> FunctionMap {
    let mut map = FunctionMap(HashMap::new());

    map.0.insert("keyMatch", Box::new(builtin_operators::key_match));
    map.0.insert("keyMatch2", Box::new(builtin_operators::key_match2));
    map.0.insert("regexMatch", Box::new(builtin_operators::regex_match));
    map.0.insert("ipMatch", Box::new(builtin_operators::ip_match));

    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use eval::{to_value, Expr};

    fn cas_obj(data: &[(&'static str, &'static str)]) -> HashMap<&'static str, &'static str> {
        let obj: HashMap<&str, &str> = data.iter().cloned().collect();
        obj
    }

    #[test]
    fn test_eval() {
        let expr = Expr::new(r#"keyMatch("/foo", "/foo")"#).function("keyMatch", |v| {
            Ok(to_value(builtin_operators::key_match(
                v[0].as_str().unwrap(),
                v[1].as_str().unwrap(),
            )))
        });

        assert_eq!(expr.exec(), Ok(to_value(true)));

        let request = cas_obj(&[("sub", "alice"), ("obj", "data1"), ("act", "read")]);
        let policy = cas_obj(&[("sub", "alice"), ("obj", "data1"), ("act", "read"), ("effect", "allow")]);

        // Note: The comparisons are inside parentheses because expr doesn't respect the operator
        // precedence of '==' over '&&'.
        let expr = Expr::new("(r.sub == p.sub) && (r.obj == p.obj) && (r.act == p.act)")
            .value("r", request.clone())
            .value("p", policy);
        assert_eq!(expr.exec(), Ok(to_value(true)));

        let policy = cas_obj(&[("sub", "bob"), ("obj", "data1"), ("act", "read"), ("effect", "allow")]);
        let expr = Expr::new("(r.sub == p.sub) && (r.obj == p.obj) && (r.act == p.act)")
            .value("r", request.clone())
            .value("p", policy);
        assert_eq!(expr.exec(), Ok(to_value(false)));
    }
}
