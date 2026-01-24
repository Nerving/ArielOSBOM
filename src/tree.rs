use cargo_metadata::{Metadata, Node, Package};

use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
};

fn parse_envs(input: &str) -> Vec<String> {
    // TODO maybe: comment out why "/' and \ are treated the way they are (tldr: for environment variables to be properly recognized by Command)

    let characters = input.chars();

    let mut envs_vector: Vec<String> = vec![];

    let mut state: char = 'n';  // states: 'n' = none; 'k' = key; 'v' = value; '\"' in double quotes; '\'' in single quotes; '$' = ignore
    let mut return_state = 'n';
    // maybe make states "prettier" with an enum later?
    let mut current_pair: Vec<char> = vec![];
    let mut last_char = ' ';
    for character in characters {
        match state {
            'n' => {
                match character {
                    ' ' => {},
                    '$' => {
                        state = '$';
                        return_state = 'n';
                        continue;
                    },
                    _ => {  // assumption(fact?): always key-value pair; key never has any "/'
                        state = 'k';
                        current_pair = vec![];
                    },
                };    
            },
            '$' => {
                match character {
                    '}' => {
                        state = return_state;
                        continue;
                    }
                    _ => continue,
                };
            },
            'k' => {    // again: assumption: key only normal characters, no "/' or whatever
                match character {
                    '=' => state = 'v',
                    _ => {},
                };
            },
            'v' => {
                match character {   // assumption: no escaped \" if not in a "/' already
                    '\"' => {
                        return_state = 'v';
                        state = '\"';
                        continue;
                    },
                    '\'' => {   // assumption: no escaped \' if not in a "/' already
                        return_state = 'v';
                        state = '\'';
                        continue;
                    },
                    '$' => {
                        state = '$';
                        return_state = 'v';
                        continue;
                    },
                    ' ' => {
                        envs_vector.push(current_pair.iter().collect());
                        state = 'n';
                    },
                    _ => {},
                };
            },
            '\"' => {
                match character {
                    '$' => {
                        state = '$';
                        return_state = '\"';
                        continue;
                    },
                    '\"' => {
                        if last_char != '\\' {
                            state = 'v';
                            continue;
                        }
                        else {}
                    },
                    '\\' => {
                        last_char = '\\';
                        continue;
                    },
                    _ => {},  
                };
            },
            '\'' => {
                match character {
                    '$' => {
                        state = '$';
                        return_state = '\"';
                        continue;
                    },
                    '\'' => {
                        if last_char != '\\' {
                            state = 'v';
                            continue;
                        }
                        else {}
                    },
                    '\\' => {
                        last_char = '\\';
                        continue;
                    },
                    _ => {},  
                };
            },
            _ => panic!("Invalid state"),
        };
        current_pair.push(character);
        last_char = character;
    }

    return envs_vector;
}

fn extract_build_command(project_path: &Path) -> String {

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

        return lines[3].to_string();
    }

fn generate_cargo_tree_output(project_path: &Path) -> Vec<u8> {

        let build_command = extract_build_command(&project_path);

        let command_split: Vec<&str> = build_command.split(" cargo ").collect();

        let mut right_split = command_split[1].split(" ");

        // should always start with OPENOCD_[...], unless other funky stuff can happen at build?
        let envs: Vec<String> = parse_envs(command_split[0].rsplit_once("&&").unwrap().1);

        let envs_key_value: Vec<(&str, &str)> = envs
            .iter()
            .map(|key_arg| key_arg.split_once('=').unwrap())
            .collect();

        let features = right_split.find(|string| string.contains("--features")).unwrap();

        let command_output = Command::new("cargo")
                .envs(envs_key_value)
                .current_dir(project_path)
                .arg("tree")
                .arg("--prefix")
                .arg("none")
                .arg(&features)
                .output()
                .expect("Something failed with cargo tree")
                .stdout;
        return command_output;
}

pub fn generate_cargo_tree_data(project_path: &Path) -> HashSet<String> {

    let tree_data = match String::from_utf8(generate_cargo_tree_output(project_path)) {
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

    // missing 6 crates here, TODO; reason: missing features in metadata command
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

        if node.id.repr.contains("@") {
            let node_split = node.id.repr.rsplit_once("#").unwrap().1;
            (name, version) = node_split.split_once("@").unwrap();
        }
        else {
            (name, version) = node.id.repr.rsplit_once("/").unwrap().1.split_once("#").unwrap();
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