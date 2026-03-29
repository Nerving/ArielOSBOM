mod component;
mod cliarg;
mod sbom;
mod tree;

use crate::{
        cliarg::Args,
        sbom::{RawSbom, write_sbom_to_file},
        tree::{filter_cargo_metadata, generate_cargo_tree_data},
};

use cargo_lock::{Lockfile, Error as LockError, Package as LockPackage};
use cargo_metadata::{Error as MetadataError, Metadata, MetadataCommand};
use clap::{Parser};
use serde::{Deserialize, Serialize};

use std::{
        collections::HashSet, 
        fs::File, 
        io::{BufRead, BufReader}, 
        path::Path, 
        process::Command,
};

fn extract_build_command_from_buildlocal(project_path: &Path) -> String {

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

fn extract_build_command_from_compile_commands(project_path: &Path) -> String {

    let file = match File::open(format!("{}compile_commands.json", project_path.display())) {
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

struct ArielOsBuildCommand {
        pub envs: Vec<String>,
        // pub config: String,
        pub features: String,
        // pub destination: PathBuf,
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

fn generate_cargo_metadata(root_path: &Path, manifest_path: &Path, features: &String) -> Result<Metadata, MetadataError> {
        let mut metadata_command = MetadataCommand::default();
                metadata_command.current_dir(root_path);
                metadata_command.manifest_path(manifest_path);
                metadata_command.features(cargo_metadata::CargoOpt::SomeFeatures(
                        features
                                .split_once("=").unwrap().1
                                .split(",")
                                .map(|feature| feature.into())
                                .collect()
                ));
        metadata_command.exec()
}

fn generate_cargo_lock_data(root_path: &Path, lock_path: &Path) -> Result<Lockfile, LockError> {
        Lockfile::load(format!("{}{}", root_path.display(), lock_path.display()))
}

fn extract_missing_checksums(checklist: HashSet<&String>, import_lockdata: Vec<LockPackage>) -> Vec<LockPackage> {
    import_lockdata
        .into_iter()
        .filter(|package| checklist.contains(&format!("{} v{}", package.name.as_str(), package.version)))
        .collect::<Vec<LockPackage>>()
}

struct Builder<'a>(&'a str);

fn main() {
    let cli_args = Args::parse();

    if !(cli_args.project_root_path.exists()) { panic!("Cannot find project root path:\n{:?}", cli_args.project_root_path); }

    // future: do not generate each sbom entirely seperately but fill "database" of components first and then generate all boms accordingly
        
    for builder in &cli_args.builders {
        
        let mut sbom = RawSbom::new();

        let extracted_build_command: String; 
        let mut detected_builder = Builder("undetected");
        if builder == "none" {
            println!("no builders specified, using last build command");
            extracted_build_command = extract_build_command_from_buildlocal(&cli_args.project_root_path);
        } else {
            println!("generating build files for builder {}", builder);
            detected_builder.0 = builder;
            let laze_output = Command::new("laze")
                .current_dir(&cli_args.project_root_path)
                .arg("build")
                .arg("-G")
                .arg("-C")
                .arg(&cli_args.project_manifest_path
                        .clone()
                        .into_os_string()
                        .to_str()
                        .unwrap()
                        .rsplit_once("Cargo.toml")
                        .unwrap().0
                )
                .arg("-c")
                .arg("-b")
                .arg(builder)
                .output();

            match laze_output {
                Ok(output) => {
                    if output.status.success() {
                        println!("generated build files for builder {}\n", builder);
                    } else {
                        println!("failed to generate build files for builder {}:\n\t{}", builder, String::from_utf8_lossy(&output.stderr));
                        continue;
                    }
                },
                Err(e) => println!("laze ran into a problem building for {}: {}", builder, e)
            };

            extracted_build_command = extract_build_command_from_compile_commands(&cli_args.project_root_path);
        }

        let build_command: ArielOsBuildCommand = parse_build_command(extracted_build_command);
        if builder == "none" {
            let board_env = build_command.envs.iter().find(|env| env.contains("CONFIG_BOARD="));
            match board_env {
                Some(board) => {
                    detected_builder.0 = board.split_once('=').unwrap().1;
                    println!("found builder {}\n", detected_builder.0);
                }
                None => println!("failed to determine builder")
            };
        }

        let tree_data = generate_cargo_tree_data(&cli_args.project_root_path, &cli_args.project_manifest_path, &build_command);

        // will need error handling in case metadata fails -> manual data gathering then?
        let metadata = match generate_cargo_metadata(&cli_args.project_root_path, &cli_args.project_manifest_path, &build_command.features) { 
                Ok(metadata) => metadata,
                Err(e) => panic!("Error generating cargo metadata:\n{e:?}"),
        };

        let mut lock_data = match generate_cargo_lock_data(&cli_args.project_root_path, &cli_args.project_lock_path) {
                Ok(lock_data) => lock_data,
                Err(e)=> panic!("Error loading Cargo.lock data:\n{e:?}"),
        };

        let additional_lock_data = match generate_cargo_lock_data(
            &cli_args.project_root_path.join(&cli_args.arielos_import_path),
            &cli_args.project_lock_path) {
                Ok(lock_data) => lock_data,
                Err(e) => panic!("Error loading ArielOS import Cargo.lock data:\n{e:?}")
            };

        let lock_data_map: HashSet<String> = lock_data.packages
            .iter()
            .map(|package| format!("{} v{}", package.name.as_str(), package.version))
            .collect();

        let missing_checksum_list: HashSet<&String> = HashSet::from_iter(
            tree_data
                .iter()
                .filter(|entry|
                    !lock_data_map.contains(*entry)
                )
        );

        lock_data.packages.append(&mut extract_missing_checksums(missing_checksum_list, additional_lock_data.packages));

        // filtering for: only crates that were actually compiled

        let filtered_metadata: Metadata = filter_cargo_metadata(tree_data, metadata);

        // extract information from cargo metadata
        sbom.convert_cargo_metadata_packages_to_components(&filtered_metadata, &lock_data);

        for bom_format in &cli_args.bom_formats {
            write_sbom_to_file(&mut sbom, bom_format, &cli_args.output_name, detected_builder.0);
        }
    }
}

