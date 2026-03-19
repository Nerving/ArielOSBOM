mod component;
mod cliarg;
mod sbom;
mod tree;

use crate::{
        cliarg::Args,
        sbom::{RawSbom, cyclonedx::{CycloneDxSbomV1_7}, write_sbom_to_file},
        tree::{filter_cargo_metadata, generate_cargo_tree_data},
};

use cargo_lock::{Lockfile, Error as LockError, Package as LockPackage};
use cargo_metadata::{Error as MetadataError, Metadata, MetadataCommand};
use clap::{Parser};

use std::{
        collections::HashSet, fs::File, io::{BufRead, BufReader}, path::Path
};

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


fn main() {
        let cli_args = Args::parse();

        if !(cli_args.project_root_path.exists()) { panic!("Cannot find project root path:\n{:?}", cli_args.project_root_path); }
        
        // TODO: handle stuff that might have to be handled first by CLI arguments
                // e.g. setting up logging; or "environment" for/if SBOMs to be created

        // just one for now, potentially for different devices(/projects?) in the future
        let mut sboms = RawSbom::new();

        let extracted_build_command = extract_build_command(&cli_args.project_root_path);

        let build_command: ArielOsBuildCommand = parse_build_command(extracted_build_command);

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
            &cli_args.project_root_path.join(cli_args.arielos_import_path),
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
        sboms.convert_cargo_metadata_packages_to_components(&filtered_metadata, &lock_data);

        // TODO:
                // complete missing info
                // non-Metadata/-Rust stuff

        for bom_format in &cli_args.bom_formats {
            write_sbom_to_file(&mut sboms, bom_format, &cli_args.output_name);
        }
}

