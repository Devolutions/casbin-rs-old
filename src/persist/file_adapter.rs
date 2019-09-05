use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::model::Model;
use crate::persist::{Adapter, Filter, FilteredAdapter};

#[derive(Debug)]
pub struct FileAdapter {
    path: PathBuf,
    filtered: bool,
}

impl FileAdapter {
    /// Create a FileAdapter instance.
    pub fn new<P: AsRef<Path>>(path: P, filtered: bool) -> Self {
        FileAdapter {
            path: path.as_ref().to_path_buf(),
            filtered: filtered,
        }
    }
}

impl Adapter for FileAdapter {
    /// Load all policy rules from the storage.
    fn load_policy(&self, model: &mut Model) -> Result<(), Error> {
        let mut file = File::open(&self.path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        for line in contents.lines() {
            model.load_policy_line(line)?;
        }

        Ok(())
    }

    fn save_policy(&self, _model: &mut Model) -> Result<(), Error> {
        unimplemented!()
    }

    fn add_policy(&self, _sec: &str, _ptype: &str, _rule: Vec<String>) -> Result<(), Error> {
        unimplemented!()
    }

    fn remove_policy(&self, _sec: &str, _ptype: &str, _rule: Vec<String>) -> Result<(), Error> {
        unimplemented!()
    }

    fn remove_filtered_policy(
        &self,
        _sec: &str,
        _ptype: &str,
        _field_index: i32,
        _field_values: Vec<String>,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

impl FilteredAdapter for FileAdapter {
    fn load_filtered_policy(&self, model: &mut Model, filter: Option<&Filter>) -> Result<(), Error> {
        if filter.is_none() {
            return self.load_policy(model);
        }

        let mut file = File::open(&self.path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        for line in contents.lines() {
            if filter_line(line, filter) {
                continue;
            }
            model.load_policy_line(line)?;
        }

        Ok(())
    }

    fn is_filtered(&self) -> bool {
        self.filtered
    }
}

fn filter_line(line: &str, filter: Option<&Filter>) -> bool {
    if filter.is_none() {
        return false;
    }
    let filter = filter.unwrap();

    let p: Vec<String> = line.split(',').map(|t| t.trim().to_string()).collect();

    if p.is_empty() {
        return true;
    }

    match p[0].as_str() {
        "p" => filter_words(p, &filter.p),
        "g" => filter_words(p, &filter.g),
        _ => panic!("unexpected line filter"),
    }
}

fn filter_words(line: Vec<String>, filter: &Vec<String>) -> bool {
    if line.len() < filter.len() + 1 {
        return true;
    }

    let mut skip_line = false;
    for (i, v) in filter.iter().enumerate() {
        if v.len() > 0 && v.trim() != line[i + 1].trim() {
            skip_line = true;
            break;
        }
    }

    skip_line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_policy() {
        let mut model = Model::from_file("examples/basic_model.conf").expect("failed to load model");
        let adapter = FileAdapter::new("examples/basic_policy.csv", false);
        adapter.load_policy(&mut model).expect("failed to load policy");
    }
}
