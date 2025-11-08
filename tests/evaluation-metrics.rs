mod evaluation_metrics;
use evaluation_metrics::comparison::{generate_comparisons};

use std::fs::{File};
use std::io::{BufRead, BufReader};

// TODO/IDEAS:
    // multiple test projects ~> diff. section in ini file -> diff. folder in results for each

static TEST_PATH: &'static str = "./tests/evaluation_metrics/";
static TOOL_PATH: &'static str = "./tests/evaluation_metrics/tools/";
static RESULT_PATH: &'static str = "./tests/evaluation_metrics/results/";

#[test]
fn eval_metrics() {

    let file = File::open(format!("{}config.ini", TEST_PATH)).expect("Couldn't open config.ini");
    
    let buffer = BufReader::new(file);

    // [0]: project_path, [1]: syft_version, [2]: crc_version
    let mut config_lines: Vec<String> = vec![];
    for line in buffer.lines() {
        match line {
            Ok(content) => {config_lines.push(content.split('=').last().unwrap().into());},
            Err(_) => panic!("Failed to parse ini file")
        };
    }

    generate_comparisons(&config_lines[0], &config_lines[1],&config_lines[2]);

    // TODO:
        // compare: which ones do both have, which ones does the other one not have (+ dependencies if necessary for now)
        // that happens in the comparison module xd
}