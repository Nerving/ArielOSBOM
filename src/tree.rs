use cargo_metadata::{Metadata, Node, Package};

use std::{
    collections::HashSet,
    path::Path,
    process::Command,
};

use crate::ArielOsBuildCommand;

fn generate_cargo_tree_output(project_path: &Path, manifest_path: &Path, envs: &Vec<String>, features: &String) -> Vec<u8> {

        let envs_key_value: Vec<(&str, &str)> = envs
            .iter()
            .map(|key_arg| key_arg.split_once('=').unwrap())
            .collect();

        let command_output = Command::new("cargo")
                .envs(envs_key_value)
                .current_dir(project_path)
                .arg("tree")
                .arg("--prefix")
                .arg("none")
                .arg("--manifest-path")
                .arg(manifest_path)
                .arg(&features)
                .output()
                .expect("Something failed with cargo tree")
                .stdout;
        return command_output;
}

pub fn generate_cargo_tree_data(project_path: &Path, manifest_path: &Path, build_command: &ArielOsBuildCommand) -> HashSet<String> {

    let tree_data = match String::from_utf8(generate_cargo_tree_output(project_path, manifest_path, &build_command.envs, &build_command.features)) {
        Ok(data) => data,
        Err(_) => panic!("Could not convert cargo tree output from UTF8 to str.")
    };

    // just basic filtering for now, without checking for features or potentially checking accuracy of dependencies in cargo metadata

    let mapped_tree_data_lines: Vec<String> = tree_data
                                                .lines()
                                                .map(|string| string.split(" (").next().unwrap().to_string())
                                                .collect();
    
    let tree_set: HashSet<String> = HashSet::from_iter(mapped_tree_data_lines);

    return tree_set;
}

pub fn filter_cargo_metadata(tree_set: HashSet<String>, mut metadata: Metadata) -> Metadata {

    let package_count = tree_set.len();

    let mut new_package_vec: Vec<Package> = Vec::with_capacity(package_count);
    let mut new_node_dep_vec: Vec<Node> = Vec::with_capacity(package_count);

    let mut package_id_set: HashSet<String> = HashSet::new();

    for package in &metadata.packages {
        if tree_set.contains(&format!("{} v{}", package.name, package.version.to_string())) {
            new_package_vec.push(package.clone());
            package_id_set.insert(package.id.repr.clone());
        }
    }

    let resolve_unwrap = metadata.resolve.as_mut().unwrap();

    for node in &resolve_unwrap.nodes {
        let name: &str;
        let version: &str;

        // case cargo; registry+https:...; also some git cases
        if node.id.repr.contains("@") {
            let node_split = node.id.repr.rsplit_once("#").unwrap().1;
            (name, version) = node_split.split_once("@").unwrap();
        }
        else {
            // case for some git imports; git+https:...
            if node.id.repr.contains("git+") {
                (name, version) = (
                    node.id.repr.rsplit_once("/").unwrap().1.split_once("?").unwrap().0,
                    node.id.repr.rsplit_once("#").unwrap().1
                );

            }
            else {
                // case local import; path+file:...
                (name, version) = node.id.repr.rsplit_once("/").unwrap().1.split_once("#").unwrap();
            }
        }

        if tree_set.contains(
            &format!("{} v{}", name, version)
        ) {
            let mut new_node = node.clone();

            new_node.deps = node.deps
                                .iter()
                                .filter(|dep| package_id_set.contains(&dep.pkg.repr))
                                .map(|node_dep| node_dep.clone())
                                .collect();

            new_node.dependencies = node.dependencies
                                        .iter()
                                        .filter(|dependency| package_id_set.contains(&dependency.repr))
                                        .map(|pkg_id| pkg_id.clone())
                                        .collect();

            new_node_dep_vec.push(new_node);
        }
    }

    metadata.packages = new_package_vec;
    resolve_unwrap.nodes = new_node_dep_vec;

    return metadata;
}