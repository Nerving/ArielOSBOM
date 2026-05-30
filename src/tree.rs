use cargo_metadata::{Metadata, Node, Package};

use std::{
    collections::HashSet,
    fs::File,
    io::Write,
    path::Path,
    process::Command,
};

use crate::{
    ArielOsBuildContext,
    sbom::FileFormat,
};


pub fn generate_cargo_tree_output(context: &ArielOsBuildContext) -> Vec<u8> {

    let envs_key_value: Vec<(&str, &str)> = context.build_command.envs
    .iter()
    .map(|key_arg| key_arg.split_once('=').unwrap())
    .collect();

    Command::new("cargo")
        .envs(envs_key_value)
        .current_dir(&context.root_path)
        .arg("tree")
        .arg("--prefix")
        .arg("none")
        .arg("--manifest-path")
        .arg(&context.manifest_path)
        .arg(&context.build_command.features)
        .output()
        .expect("Something failed with cargo tree")
        .stdout

}

pub fn generate_cargo_tree_component_list(tree_data: Vec<u8>) -> HashSet<String> {

    let tree_data = match String::from_utf8(tree_data) {
        Ok(data) => data,
        Err(_) => panic!("could not convert cargo tree output from UTF8 to str.")
    };

    // just basic filtering for now, without checking for features or potentially checking accuracy of dependencies in cargo metadata

    let mapped_tree_data_lines: Vec<String> = tree_data
        .lines()
        .map(|string| string.split(" (").next().unwrap().to_string())
        .collect();
    
    HashSet::from_iter(mapped_tree_data_lines)

}

// redo and/or restructure?
pub fn filter_cargo_metadata(tree_set: &HashSet<String>, mut metadata: Metadata) -> Metadata {

    let package_count = tree_set.len();

    let mut new_package_vec: Vec<Package> = Vec::with_capacity(package_count);
    let mut new_node_dep_vec: Vec<Node> = Vec::with_capacity(package_count);

    let mut package_id_set: HashSet<String> = HashSet::new();

    for package in &metadata.packages {
        if tree_set.contains(&format!("{} v{}", package.name, package.version)) {
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
                                .filter(|dep| package_id_set.contains(&dep.pkg.repr)).cloned()
                                .collect();

            new_node.dependencies = node.dependencies
                                        .iter()
                                        .filter(|dependency| package_id_set.contains(&dependency.repr)).cloned()
                                        .collect();

            new_node_dep_vec.push(new_node);
        }
    }

    metadata.packages = new_package_vec;
    resolve_unwrap.nodes = new_node_dep_vec;

    metadata
}

pub fn write_tree_to_file(tree: Vec<u8>, file_name: &str, output_dir: &Path, builder: &str) {

    let file_format = FileFormat::Txt;
    let full_file_name = format!("{}_{}.tree.{}", file_name, builder, file_format);
    let mut file = match File::create(Path::new(output_dir).join(&full_file_name)) {
        Ok(file) => file,
        Err(e) => panic!("Could not create file: {}: {}", full_file_name, e),
    };

    file.write_all(&tree)
        .expect("failed to write cargo tree to file");

}