use std::path::Path;
use std::{collections::HashMap, process::Command};

use cargo_lock::Checksum;
use cargo_metadata::{Node, Package, PackageId};

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    CrateId, CrateSource,
    tree::{CargoTreeGraph, TreeDependency},
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: Version,
    pub id: String,
    pub creators: Vec<String>, // TODO: enhance authors
    // pub filename: Option<String>,
    pub licenses: Option<String>, // more specified later
    pub identifiers: Vec<String>, // more specified later for Hash, SWHID, ...

    pub vcs: Option<String>,
    pub metadata_repository: Option<String>,
    pub metadata_website: Option<String>,

    // pub executable_property: Option<bool>,
    // pub archive_property: Option<bool>,
    // pub structured_property: Option<bool>,

    // pub uri_source_code: Option<String>,
    // pub hash_source_code: Option<String>,
    // pub uri_deployable_form: Option<String>,
    // pub url_security_text: Option<String>,
    pub dependencies: Vec<Dependency>,
}

impl Component {
    // bunch of stuff not yet addressed, for future
    pub fn create_component_from_cargo_data(
        package: &Package,
        resolve_node: &Node,
        checksum: Option<&Checksum>,
        tree_graph: &CargoTreeGraph,
        node_index: usize,
        crate_identifier_map: &HashMap<PackageId, CrateId>,
    ) -> Self {
        let identifiers = if let Some(hash) = checksum {
            vec![hash.to_string()]
        } else {
            Vec::new()
        };

        let mut dependencies: Vec<Dependency> = Vec::new();
        for dependency in &resolve_node.dependencies {
            if let Some(identifier) = crate_identifier_map.get(dependency) {
                let mut dependency_summary = Dependency::new(dependency);
                for tree_dependency in &tree_graph.dependencies[node_index] {
                    if &tree_graph.nodes[tree_dependency.node_index] == identifier {
                        dependency_summary.update(tree_dependency);
                    }
                }
                if dependency_summary.is_valid() {
                    dependencies.push(dependency_summary)
                };
            } else {
                panic!(); // should not happen I guess
            }
        }

        let vcs = determine_vcs(&tree_graph.nodes[node_index].source, package);

        Component {
            id: package.id.repr.clone(),
            name: package.name.to_string(),
            version: package.version.clone(),
            creators: package.authors.clone(),
            // filename: None,
            licenses: package.license.clone(),
            identifiers,
            vcs,
            metadata_repository: package.repository.clone(),
            metadata_website: package.homepage.clone(),
            // executable_property: None,
            // archive_property: None,
            // structured_property: None,

            // uri_source_code: package.repository.clone(),
            // hash_source_code: None,
            // uri_deployable_form: None,
            // url_security_text: None,
            dependencies,
        }
    }
}

fn determine_vcs(crate_source: &CrateSource, package: &Package) -> Option<String> {
    match crate_source {
        CrateSource::CratesIo => package.repository.clone(),
        CrateSource::External(url) => Some(url.clone().replace("?rev=", "/tree/")),
        CrateSource::Local(path) => {
            if package.id.repr.contains("ariel-os/src/") {
                try_get_local_git_source(path)
            } else {
                None
            }
        }
        CrateSource::LocalNoPath => panic!("unexpected CrateSource type: LocalNoPath"),
    }
}

fn try_get_local_git_source(path: &Path) -> Option<String> {
    let git_url;
    match Command::new("git")
        .current_dir(path)
        .arg("config")
        .arg("--get")
        .arg("remote.origin.url")
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                git_url = String::from_utf8(output.stdout)
                    .unwrap()
                    .trim()
                    .trim_end_matches(".git")
                    .to_owned();
            } else {
                return None;
            }
        }
        Err(_) => return None,
    };

    let git_commit_hash;
    match Command::new("git")
        .current_dir(path)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                git_commit_hash = String::from_utf8(output.stdout).unwrap().trim().to_owned();
            } else {
                return None;
            }
        }
        Err(_) => return None,
    };
    Some(format!("{git_url}/tree/{git_commit_hash}"))
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub id: String,
    pub build: bool,
    pub normal: bool,
    pub proc_macro: bool,
}

impl Dependency {
    fn new(package_id: &PackageId) -> Self {
        Dependency {
            id: package_id.to_string(),
            build: false,
            normal: false,
            proc_macro: false,
        }
    }

    fn update(&mut self, tree_dependency: &TreeDependency) {
        self.build = self.build || tree_dependency.is_build();
        self.normal = self.normal || tree_dependency.is_normal();
        self.proc_macro = self.proc_macro || tree_dependency.is_proc_macro;
    }

    fn is_valid(&self) -> bool {
        self.build || self.normal
    }
}
