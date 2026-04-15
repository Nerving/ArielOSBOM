use std::{
    collections::HashSet, 
    fs::{self, File}, 
    path::{Path, PathBuf}, 
    process::Command
};

use jsonschema;
use serde::{Serialize, Deserialize};
use serde_json;

#[cfg(target_os = "windows")]
const binary_path: &str = "target/debug/arielosbom.exe";

#[cfg(not(target_os = "windows"))]
const BINARY_PATH: &str = "target/debug/arielosbom";

const IMPORT_PATH: &str = "tests/import";

const OUTPUT_PATH: &str = "tests/output";

const SCHEMA_PATH: &str = "tests/schemata";

fn setup_environment() {

    let import_path = Path::new(IMPORT_PATH);
    if !import_path.exists() {
        Command::new("git")
            .arg("clone")
            .arg("https://github.com/ariel-os/ariel-os.git")
            .arg(IMPORT_PATH)
            .output()
            .expect("Failed to import Ariel OS repo");
    }
    assert!(import_path.exists());

    assert!(Path::new(BINARY_PATH).exists(), "Cannot find binary to execute: {}", BINARY_PATH);

    let output_path = Path::new(OUTPUT_PATH);
    if !(output_path.exists()) {
        match fs::create_dir(OUTPUT_PATH) {
            Ok(_) => println!("created output directory: {}\n", OUTPUT_PATH),
            Err(e) => panic!("failed to created output directory: {:?}\n", e)
        };
    }
    assert!(output_path.exists());

}

#[test]
fn general_test() {

    setup_environment();

    // TODO: implement options for other/more/all examples, builders?

    // generate SBOM
    let sbom_generation = Command::new(BINARY_PATH)
        .arg("-r")
        .arg(Path::new(IMPORT_PATH))
        .arg("-m")
        .arg(["examples", "coap-client", "Cargo.toml"].iter().collect::<PathBuf>())
        .arg("-b")
        .arg("cdx_1.6")
        .arg("--builders")
        .arg("nrf52840dk")
        .arg("-o")
        .arg("full-test")
        .arg("--output-directory")
        .arg(Path::new(OUTPUT_PATH))
        .arg("-l")
        .arg("Cargo.lock")
        .arg("-i")
        .arg(".")
        .output();

    match sbom_generation {
        Ok(_) => assert!([OUTPUT_PATH, "full-test_nrf52840dk.cdx.json"].iter().collect::<PathBuf>().exists(), "failed to find generated SBOM file"),
        Err(e) => panic!("failed to generate SBOM: {}", e)
    };

    // check if CycloneDx conform
    let schema_file = fs::File::open([SCHEMA_PATH, "cyclonedx_1.6_schema.json"].iter().collect::<PathBuf>())
        .expect("failed to open json schema file");
    let cyclonedx_16_schema = serde_json::from_reader(schema_file)
        .expect("failed to parse json schema");
    let sbom_file = fs::File::open([OUTPUT_PATH, "full-test_nrf52840dk.cdx.json"].iter().collect::<PathBuf>())
        .expect("failed to open SBOM file");
    let to_validate = serde_json::from_reader(sbom_file)
        .expect("failed to parse SBOM");
    assert!(jsonschema::is_valid(&cyclonedx_16_schema, &to_validate));

    // check if components match

    let mut component_set: HashSet<String> = HashSet::new();
    let components = &to_validate["components"].as_array().unwrap();
    for component in components.iter() {
        component_set.insert(format!("{} v{}", component["name"], component["version"]).replace("\"", ""));
    }

    let build_command = parse_build_command(extract_build_command_from_compile_commands());

    let envs_key_value: Vec<(&str, &str)> = build_command.envs
            .iter()
            .map(|key_arg| key_arg.split_once('=').unwrap())
            .collect();

    let cargo_tree_output = String::from_utf8(Command::new("cargo")
            .envs(envs_key_value)
            .current_dir(Path::new(IMPORT_PATH))
            .arg("tree")
            .arg("--prefix")
            .arg("none")
            .arg("--manifest-path")
            .arg(["examples","coap-client","Cargo.toml"].iter().collect::<PathBuf>())
            .arg(&build_command.features)
            .output()
            .expect("Something failed with cargo tree")
            .stdout)
            .expect("failed to parse cargo tree output");
    
    let cargo_tree_set: HashSet<String> = cargo_tree_output
        .lines()
        .map(|line| line.split(" (").next().unwrap().to_string())
        .collect();

    assert!(cargo_tree_set.intersection(&component_set).collect::<HashSet<&String>>().len() == cargo_tree_set.len(), "SBOM components and cargo tree output do not match");
}


// copied necessities from main program

fn extract_build_command_from_compile_commands() -> String {

    let compile_commands_path: &Path = Path::new("compile_commands.json");

    let file = match File::open([Path::new(IMPORT_PATH), compile_commands_path].iter().collect::<PathBuf>()) {
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