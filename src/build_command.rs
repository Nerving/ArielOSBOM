use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
};

use serde::{Deserialize, Serialize};

use crate::ArielOsBuildContext;

const BUILD_LOCAL_PATH: &str = "build/build-local.ninja";
const COMPILE_COMMANDS_PATH: &str = "compile_commands.json";

#[derive(PartialEq)]
pub struct ArielOsBuildCommand {
    pub envs: Vec<String>,
    // pub config: String,
    pub features: String,
    // pub destination: PathBuf,
}

impl Default for ArielOsBuildCommand {
    fn default() -> ArielOsBuildCommand {
        ArielOsBuildCommand {
            envs: vec![],
            features: "".to_string(),
        }
    }
}

impl ArielOsBuildCommand {
    pub fn from_buildlocal(project_path: &Path) -> (ArielOsBuildCommand, String) {
        let build_command = ArielOsBuildCommand::parse_build_command(
            CompileCommandsJson::from_buildlocal(project_path),
        );
        let detected_builder = build_command.get_builder();

        (build_command, detected_builder)
    }

    pub fn from_compile_commands_json(project_path: &Path) -> ArielOsBuildCommand {
        ArielOsBuildCommand::parse_build_command(CompileCommandsJson::from_compile_commdands_json(
            project_path,
        ))
    }

    fn parse_build_command(build_command: CompileCommandsJson) -> ArielOsBuildCommand {
        let command_split: (&str, &str) = build_command.command.split_once(" cargo ").unwrap();

        // should always start with OPENOCD_[...], unless other funky stuff can happen at build?
        let envs: Vec<String> = parse_envs(command_split.0.rsplit_once("&&").unwrap().1);

        let mut right_split = command_split.1.split_whitespace();

        ArielOsBuildCommand {
            envs,
            // config: right_split.find(|string| string.contains("ariel-os-cargo")).unwrap().to_string(),
            features: right_split
                .find(|string| string.contains("--features"))
                .unwrap()
                .to_string(),
            // destination:    right_split.find(|string| string.contains("/build/bin")).unwrap().into(),
        }
    }

    fn get_builder(&self) -> String {
        let board_env = self.envs.iter().find(|env| env.contains("CONFIG_BOARD="));
        let mut detected_builder = "undetected";
        match board_env {
            Some(board) => {
                detected_builder = board.split_once('=').unwrap().1;
                println!("found builder {}\n", detected_builder);
            }
            None => println!("failed to determine builder"),
        };

        detected_builder.to_string()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CompileCommandsJson {
    command: String,
    //output: String,
}

impl CompileCommandsJson {
    // proper error propagation later
    pub fn generate_compile_commands_file(context: &ArielOsBuildContext) {
        println!("generating build files for builder {}", context.builder);

        let laze_output = Command::new("laze")
            .current_dir(&context.root_path)
            .arg("-C")
            .arg(
                Path::new(".").join(
                    context
                        .manifest_path
                        .clone()
                        .into_os_string()
                        .to_str()
                        .unwrap()
                        .rsplit_once("Cargo.toml")
                        .unwrap()
                        .0,
                ),
            )
            .arg("build")
            .arg("-G")
            .arg("-c")
            .arg("-b")
            .arg(&context.builder)
            .output();

        match laze_output {
            Ok(output) => {
                if output.status.success() {
                    println!("generated build files for builder {}\n", context.builder);
                } else {
                    match env::var("TESTING") {
                        Ok(value) if value == "1" => panic!(
                            "SBOM generation failed for builder {}:\n\t{}",
                            context.builder,
                            String::from_utf8_lossy(&output.stderr)
                        ),
                        _ => println!(
                            "failed to generate build files for builder {}:\n\t{}",
                            context.builder,
                            String::from_utf8_lossy(&output.stderr)
                        ),
                    };
                }
            }
            Err(_) => println!(
                "error executing laze for builder {}: {:?}",
                context.builder,
                laze_output.err()
            ),
        };
    }

    fn from_buildlocal(project_path: &Path) -> CompileCommandsJson {
        let file = match File::open(Path::new(project_path).join(BUILD_LOCAL_PATH)) {
            Ok(file) => file,
            Err(e) => panic!("Could not open build-local.ninja: {}", e),
        };

        let reader = BufReader::new(file);
        let lines: Vec<String> = reader
            .lines()
            .collect::<Result<Vec<String>, std::io::Error>>()
            .expect("Failed to read build-local.ninja");

        CompileCommandsJson {
            command: lines[3].to_string(),
            //output: lines[8].strip_prefix("build ").unwrap().strip_suffix(": $").unwrap().to_string()
        }
    }

    fn from_compile_commdands_json(project_path: &Path) -> CompileCommandsJson {
        let file = match File::open(Path::new(project_path).join(COMPILE_COMMANDS_PATH)) {
            Ok(file) => file,
            Err(e) => panic!("Could not open compile_commands.json: {}", e),
        };

        let compile_commands: Vec<CompileCommandsJson> =
            serde_json::from_reader(file).expect("Failed to parse compile_commands.json");

        compile_commands[0].clone()
    }
}

pub fn parse_envs(input: &str) -> Vec<String> {
    let characters = input.chars();

    let mut envs_vector: Vec<String> = vec![];

    let mut state: char = 'n'; // states: 'n' = none; 'k' = key; 'v' = value; '\"' in double quotes; '\'' in single quotes; '$' = ignore
    let mut return_state = 'n';
    // maybe make states "prettier" with an enum later?
    let mut current_pair: Vec<char> = vec![];
    let mut last_char = ' ';
    for character in characters {
        match state {
            'n' => {
                match character {
                    ' ' => {}
                    '$' => {
                        state = '$';
                        return_state = 'n';
                        continue;
                    }
                    _ => {
                        // assumption(fact?): always key-value pair; key never has any "/'
                        state = 'k';
                        current_pair = vec![];
                    }
                };
            }
            '$' => {
                match character {
                    '}' => {
                        state = return_state;
                        continue;
                    }
                    _ => continue,
                };
            }
            'k' => {
                // again: assumption: key only normal characters, no "/' or whatever
                if character == '=' {
                    state = 'v'
                }
            }
            'v' => {
                match character {
                    // assumption: no escaped \" if not in a "/' already
                    '\"' => {
                        return_state = 'v';
                        state = '\"';
                        continue;
                    }
                    '\'' => {
                        // assumption: no escaped \' if not in a "/' already
                        return_state = 'v';
                        state = '\'';
                        continue;
                    }
                    '$' => {
                        state = '$';
                        return_state = 'v';
                        continue;
                    }
                    ' ' => {
                        envs_vector.push(current_pair.iter().collect());
                        state = 'n';
                    }
                    _ => {}
                };
            }
            '\"' => {
                match character {
                    '$' => {
                        state = '$';
                        return_state = '\"';
                        continue;
                    }
                    '\"' if last_char != '\\' => {
                        state = 'v';
                        continue;
                    }
                    '\\' => {
                        last_char = '\\';
                        continue;
                    }
                    _ => {}
                };
            }
            '\'' => {
                match character {
                    '$' => {
                        state = '$';
                        return_state = '\"';
                        continue;
                    }
                    '\'' if last_char != '\\' => {
                        state = 'v';
                        continue;
                    }
                    '\\' => {
                        last_char = '\\';
                        continue;
                    }
                    _ => {}
                };
            }
            _ => panic!("Invalid state"),
        };
        current_pair.push(character);
        last_char = character;
    }

    envs_vector
}
