use std::{
    collections::{HashSet}, 
    fs::{File}, 
    io::Error,
    path::{Path}, 
    process::{Command, Output},
};

use jsonschema;
use serde::{Serialize, Deserialize};
use serde_json;

mod common;
use common::{
    *,
    CONSTPATHS as PATHS,
};

const TEMP_FULL_FILE_NAME_MAIN_REPO: &str = "e2e-main-repo_nrf52840dk.1-6.cdx.json";
const TEMP_FULL_FILE_NAME_OUT_OF_TREE: &str = "e2e-oot_nrf52840dk.1-6.cdx.json";

fn generate_sbom(example: bool, output_name: &str) -> Result<Output, Error> {
    
    generate_test_sbom(
        Some(create_e2e_envs()),
        Path::new(if example {PATHS.ariel_os} else {PATHS.out_of_tree}), 
        &vec!["cdx_1.6"], 
        Some(vec!["nrf52840dk"]), 
        output_name, 
        if example {Some(Path::new("examples").join("coap-client").join("Cargo.toml"))} else {None}, 
        None, 
        if example {Some(Path::new("."))} else {Some(Path::new("../ariel-os"))},
    )
}

fn generate_tree_output(build_command: &ArielOsBuildCommand, envs: Vec<(&str, &str)>, example: bool) -> String {
    String::from_utf8(Command::new("cargo")
        .envs(envs)
        .current_dir(Path::new(if example {PATHS.ariel_os} else {PATHS.out_of_tree}))
        .arg("tree")
        .arg("--prefix")
        .arg("none")
        .arg("--manifest-path")
        .arg(if example {Path::new("examples").join("coap-client").join("Cargo.toml")} else  {Path::new("Cargo.toml").to_path_buf()})
        .arg(&build_command.features)
        .output()
        .expect("Something failed with cargo tree")
        .stdout)
        .expect("failed to parse cargo tree output")
}

fn generate_tree_set(tree_output: String) -> HashSet<String> {
    tree_output
        .lines()
        .map(|line| line.split(" (").next().unwrap().to_string())
        .collect()
}

#[test]
fn e2e_main_repo() {

    common::check_environment();

    // TODO: implement options for other/more/all examples, builders?

    // generate SBOM
    let output = generate_sbom(true, "e2e-main-repo");

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_MAIN_REPO).exists(), "failed to find generated SBOM file");
    
    // check if CycloneDx conform
    let cyclonedx_16_schema = parse_sbom(
        &Path::new(PATHS.schemata).join("cyclonedx_1.6.json"), 
        "CycloneDx 1.6 schema");
    
    let to_validate = parse_sbom(
        &Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_MAIN_REPO), 
        "error_message"
    );

    assert!(jsonschema::is_valid(&cyclonedx_16_schema, &to_validate));

    // check if components match

    let mut component_set: HashSet<String> = HashSet::new();
    let components = &to_validate["components"].as_array().unwrap();
    for component in components.iter() {
        component_set.insert(format!("{} v{}", component["name"], component["version"]).replace("\"", ""));
    }

    let build_command = parse_build_command(extract_build_command_from_compile_commands(PATHS.ariel_os));

    let envs: Vec<(&str, &str)> = build_command.envs
            .iter()
            .map(|key_arg| key_arg.split_once('=').unwrap())
            .collect();

    let cargo_tree_output = generate_tree_output(&build_command, envs, true);
    
    let cargo_tree_set: HashSet<String> = generate_tree_set(cargo_tree_output);

    assert!(cargo_tree_set.symmetric_difference(&component_set).collect::<HashSet<&String>>().is_empty(), "SBOM components and cargo tree output do not match");
    
}

#[test]
fn e2e_out_of_tree() {

    common::check_environment();

    // TODO: implement options for other/more/all examples, builders?

    // generate SBOM
    let output = generate_sbom(false, "e2e-oot");

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_OUT_OF_TREE).exists(), "failed to find generated SBOM file");
    
    // check if CycloneDx conform
    let cyclonedx_16_schema = parse_sbom(
        &Path::new(PATHS.schemata).join("cyclonedx_1.6.json"), 
        "CycloneDx 1.6 schema");
    
    let to_validate = parse_sbom(
        &Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_OUT_OF_TREE), 
        "error_message"
    );
    
    assert!(jsonschema::is_valid(&cyclonedx_16_schema, &to_validate));

    // check if components match

    let mut component_set: HashSet<String> = HashSet::new();
    let components = &to_validate["components"].as_array().unwrap();
    for component in components.iter() {
        component_set.insert(format!("{} v{}", component["name"], component["version"]).replace("\"", ""));
    }

    let build_command = parse_build_command(extract_build_command_from_compile_commands(PATHS.out_of_tree));

    let envs: Vec<(&str, &str)> = build_command.envs
            .iter()
            .map(|key_arg| key_arg.split_once('=').unwrap())
            .collect();

    let cargo_tree_output = generate_tree_output(&build_command, envs, false);
    
    let cargo_tree_set: HashSet<String> = generate_tree_set(cargo_tree_output);

    assert!(cargo_tree_set.symmetric_difference(&component_set).collect::<HashSet<&String>>().is_empty(), "SBOM components and cargo tree output do not match");
    
}

// copied necessities from main program because no lib.rs

fn extract_build_command_from_compile_commands(path: &str) -> String {

    let compile_commands_path: &Path = Path::new("compile_commands.json");

    let file = match File::open(Path::new(path).join(compile_commands_path)) {
        Ok(file) => file,
        Err(e) => panic!("Could not open compile_commands.json: {}", e),
    };

    let compile_commands: Vec<CompileCommandsJson> = serde_json::from_reader(file)
        .expect("Failed to parse compile_commands.json");

    compile_commands[0].command.clone()
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CompileCommandsJson {
    command: String,
}

struct ArielOsBuildCommand {
        pub envs: Vec<String>,
        // pub config: String,
        pub features: String,
        // pub destination: PathBuf,
}

fn parse_build_command(build_command: String) -> ArielOsBuildCommand {
        
        let command_split: (&str, &str) = build_command.split_once(" cargo ").unwrap();

        // should always start with OPENOCD_[...], unless other funky stuff can happen at build?
        let envs: Vec<String> = parse_envs(command_split.0.rsplit_once("&&").unwrap().1);

        let mut right_split = command_split.1.split_whitespace();
        
        ArielOsBuildCommand { 
                envs: envs, 
                // config: right_split.find(|string| string.contains("ariel-os-cargo")).unwrap().to_string(), 
                features: right_split.find(|string| string.contains("--features")).unwrap().to_string(), 
                // destination:    right_split.find(|string| string.contains("/build/bin")).unwrap().into(),        
        }
}

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