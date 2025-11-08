use cargo_metadata::{DependencyKind, Metadata, Node, Package};
use serde::{Serialize, Deserialize};
use serde_json;

use std::{
    collections::{HashMap, HashSet}, 
    fs::File, 
    io::{BufRead, BufReader}, 
    path::Path, 
    process::Command
};

#[derive(Deserialize, Serialize)]
pub struct BloatOutput {
    crates: Vec<BloatCrate>
}

#[derive(Deserialize, Serialize)]
struct BloatCrate {
    #[serde(rename = "name")]
    crate_name: String
}

// TODO: 
    // change to function output
    // capture crates by that
    // some form of list for stuff that gets recognized as unknown
impl BloatOutput {
    
    pub fn generate(project_path: &Path) -> BloatData {

        let file = match File::open(format!("{}build/build-local.ninja", project_path.display())) {
            Ok(file) => file,
            Err(e) => panic!("Could not open build-local.ninja: {}", e)        
        };

        let reader = BufReader::new(file);
        let mut lines: Vec<String> = vec![];
        for line in reader.lines() {
            match line {
                Ok(content) => lines.push(content),
                Err(_) => panic!("Failed to read build-local.ninja")
            };
        }

        let command_split: Vec<&str> = lines[3].split(" cargo ").collect();

        let (command_left, command_middle, command_right): (&str, &str, &str) = (
            &command_split[0][12..],
            "cargo bloat --crates -n 100000 --message-format json",
            &command_split[1].split(" &&").collect::<Vec<&str>>()[0]
        );

        let command_output = Command::new("sh")
                .current_dir(project_path)
                .arg("-c")
                .arg(format!("{} {}{}", command_left, command_middle, command_right))
                .output()
                .expect("Something failed with cargo bloat")
                .stdout;

        let cargo_bloat_output: BloatOutput = match serde_json::from_slice(
            &command_output
        ) {
            Ok(content) => content,
            Err(e) => panic!("Could not deserialize cargo bloat data: {}", e)
        };

        let mut bloat_set: HashSet<String> = HashSet::new();

        for bloat_crate in cargo_bloat_output.crates.iter() {
            bloat_set.insert(bloat_crate.crate_name.clone());
        }

        BloatData { set: bloat_set }

    }
}

pub struct BloatData{
    set: HashSet<String>
}

impl BloatData {

    fn contains(&self, value: &String) -> bool {
        self.set.contains(value)
    }

    pub fn filter_cargo_metadata(&self, mut metadata: Metadata) -> Metadata {

        let mut bloat_filter_set: HashSet<usize> = HashSet::new();
        let mut build_filter_set: HashSet<usize> = HashSet::new();

        // comment for self for now: everything that is in cargo bloat
        for (index, package) in metadata.packages.iter().enumerate() {
            if self.contains(&package.name.replace("-", "_")) {
                bloat_filter_set.insert(index);
            }
        }

        // for now: everything that comes directly via build dependencies from bloat packages
            // bloat_dep -> bloat_build_dep -> all other deps of bloat_build_dep (build_script analysis later?)

        let pkg_id_index_map: HashMap<&String, usize> = HashMap::from_iter(metadata.packages
                                                                            .iter()
                                                                            .enumerate()
                                                                            .map(|(index, package)| (&package.id.repr, index))
        );

        let resolve_unwrap = metadata.resolve.as_mut().unwrap();


        // initialize first layer of non-bloat deps
        // this should probably be made more readable?......
        let mut current_set: HashSet<usize> = resolve_unwrap.nodes
                                                .iter()
                                                .enumerate()
                                                .filter(|(index, _)| bloat_filter_set.contains(index))
                                                .map(
                                                    |(_, node)|
                                                    node.deps
                                                        .iter()
                                                        .filter(
                                                            |dep| 
                                                            dep.dep_kinds
                                                                .iter()
                                                                .any(|dep_kind_info|dep_kind_info.kind == DependencyKind::Build)
                                                        )
                                                        .map(|dep| pkg_id_index_map.get(&dep.pkg.repr).expect("Something went wrong retrieving the index of a package").clone())
                                                )
                                                .flatten()
                                                .collect();
        for index in &current_set { build_filter_set.insert(index.clone()); }

        while !(current_set.is_empty()) {
            let mut next_set: HashSet<usize> = HashSet::new();
            for index in current_set {
                for dep in resolve_unwrap.nodes[index].deps.iter() {
                    let dep_index = pkg_id_index_map.get(&dep.pkg.repr).unwrap().clone();
                    if build_filter_set.insert(dep_index) { next_set.insert(dep_index);}
                }
            }
            current_set = next_set;
        }

        // bools as extra set as output later for SBOM to declare packages only used relevant for build scripts?
        let combined_set: HashSet<usize> = bloat_filter_set
                                            .union(&build_filter_set)
                                            .map(|index| index.clone())
                                            .collect();
        let mut combined_array: Vec<usize> = combined_set.clone().into_iter().collect();
        combined_array.sort();
        let value = combined_set.len();

        let mut new_package_vec: Vec<Package> = Vec::with_capacity(value);
        let mut new_node_dep_vec: Vec<Node> = Vec::with_capacity(value);
        
        for index in combined_array {
            new_package_vec.push(metadata.packages[index].clone());
            new_node_dep_vec.push(create_filtered_metadata_node(&resolve_unwrap.nodes[index], &pkg_id_index_map, &combined_set));

        }

        metadata.packages = new_package_vec;
        resolve_unwrap.nodes = new_node_dep_vec;

        return metadata;
    }

}

fn create_filtered_metadata_node(node: &Node, pkg_id_index_map: &HashMap<&String, usize>, combined_set: &HashSet<usize>) -> Node {

    let mut new_node = node.clone();

    new_node.dependencies = new_node.dependencies
                                .iter()
                                .filter(|dependency| combined_set.contains(pkg_id_index_map.get(&dependency.repr).unwrap()))
                                .map(|pkg_id| pkg_id.clone())
                                .collect();
    new_node.deps = new_node.deps
                        .iter()
                        .filter(|dep| combined_set.contains(pkg_id_index_map.get(&dep.pkg.repr).unwrap()))
                        .map(|node_dep| node_dep.clone())
                        .collect();

    return new_node;
}