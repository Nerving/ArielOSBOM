use std::collections::HashMap;

use cargo_lock::Checksum;
use cargo_metadata::{Node, Package, PackageId};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    CrateId,
    tree::{CargoTreeGraph, TreeDependency},
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: Version,
    pub id: String,
    pub creators: Vec<String>, // TODO: enhance authors
    pub filename: Option<String>,
    pub licenses: Option<String>, // more specified later
    pub identifiers: Vec<String>, // more specified later for Hash, SWHID, ...
    pub executable_property: Option<bool>,
    pub archive_property: Option<bool>,
    pub structured_property: Option<bool>,

    pub uri_source_code: Option<String>,
    pub hash_source_code: Option<String>,
    pub uri_deployable_form: Option<String>,
    pub url_security_text: Option<String>,

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

        Component {
            id: package.id.repr.clone(),
            name: package.name.to_string(),
            version: package.version.clone(),
            creators: package.authors.clone(),
            filename: None,
            licenses: package.license.clone(),
            identifiers,
            executable_property: None,
            archive_property: None,
            structured_property: None,

            uri_source_code: package.repository.clone(),
            hash_source_code: None,
            uri_deployable_form: None,
            url_security_text: None,

            dependencies,
        }
    }
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
