use serde::{Deserialize};
use serde_json;

use std::{
    collections::BTreeSet, 
    env::{current_dir},
    fmt::Formatter, 
    fs::File, 
    io::{BufRead, BufReader, BufWriter, Write}, 
    path::PathBuf, 
    process::Command, 
};

// TODO/IDEAS:
    // enum for diff tools with version field e.g.
    // multiple test projects in the future ~> change path stuff

use crate::{RESULT_PATH, TOOL_PATH};

#[derive(Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct Component {
    name: String,
    version: Option<String>
}

impl std::fmt::Display for Component {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}@{}", self.name, match &self.version {
            Some(version) => version,
            None => ""
        })
    }
}

#[derive(Deserialize, Eq, PartialEq)]
struct SBOM {
    components: Vec<Component>
}

#[derive(Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Function {
    #[serde(rename = "crate")]
    crate_name: Option<String>,

    #[serde(rename = "name")]
    function_name: String
}

/* impl std::fmt::Display for Function {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.crate_name)
    }
} */

#[derive(Deserialize, Eq, PartialEq)]
struct Bloat {
    functions: Vec<Function>
}

pub fn generate_comparisons(project_path: &str, syft_version: &str, crc_version: &str) {

    generate_comparison_sboms(project_path, syft_version, crc_version);
    generate_cargo_bloat(project_path);

    let ariel_set = generate_component_set("arielosbom_eval.json".into());
    let syft_set = generate_component_set(format!("syft_{}.json", syft_version).into());
    let crc_set = generate_component_set(format!("crc_{}.json", crc_version).into());
    let bloat_set = generate_bloat_set("cargo_bloat.json".into()).iter().map(|function| function.split('?').next().unwrap().into()).collect();
    let ariel_bloat_comp_set = ariel_set.iter().map(|function| function.replace("-", "_").split('@').next().unwrap().into()).collect::<BTreeSet<String>>();

    let ariel_syft_intersection: Vec<String> = ariel_set.intersection(&syft_set).map(|component| component.clone()).collect();
    let ariel_crc_intersection: Vec<String> = ariel_set.intersection(&crc_set).map(|component| component.to_string()).collect();
    let ariel_syft_diff: Vec<String> = ariel_set.difference(&syft_set).map(|component| component.to_string()).collect();
    let ariel_crc_diff: Vec<String> = ariel_set.difference(&crc_set).map(|component| component.to_string()).collect();
    let syft_ariel_diff: Vec<String> = syft_set.difference(&ariel_set).map(|component| component.to_string()).collect();
    let crc_ariel_diff: Vec<String> = crc_set.difference(&ariel_set).map(|component| component.to_string()).collect();
    let ariel_bloat_intersection: Vec<String> = ariel_bloat_comp_set.intersection(&bloat_set).map(|component| component.clone()).collect();
    let ariel_bloat_diff: Vec<String> = ariel_bloat_comp_set.difference(&bloat_set).map(|component| component.to_string()).collect();
    let bloat_ariel_diff: Vec<String> = bloat_set.difference(&ariel_bloat_comp_set).map(|component| component.to_string()).collect();

    generate_comparison_file("syft", syft_version, ariel_syft_intersection, ariel_syft_diff, syft_ariel_diff);
    generate_comparison_file("crc", crc_version, ariel_crc_intersection, ariel_crc_diff, crc_ariel_diff);
    generate_bloat_comparison(ariel_bloat_intersection, ariel_bloat_diff, bloat_ariel_diff);
}

fn generate_comparison_file(
    compared: &str, 
    compared_version: &str,
    intersection: Vec<String>,
    ariel_diff: Vec<String>,
    tool_diff: Vec<String>
) {
    
    let file = match File::create(format!("{}ariel_{}_{}_comparison.txt", RESULT_PATH, compared, compared_version)) {
        Ok(file) => file,
        Err(e) => panic!("Could not create file {}ariel_{}_{}_comparison.txt: {}", RESULT_PATH, compared, compared_version, e)
    };

    let both = intersection.len();
    let ariel = ariel_diff.len();
    let tool = tool_diff.len();

    let mut writer = BufWriter::new(file);

    writer.write(format!("Components recognized by both tools: {}\n", both).as_bytes()).expect("failed writing to bufwriter");
    for component in intersection {
        writer.write(format!("{}\n", component.to_string()).as_bytes()).expect("failed writing to bufwriter");
    }

    writer.write(format!("\nComponents only recognized by ArielOSBOM: {}\n", ariel).as_bytes()).expect("failed writing to bufwriter");
    for component in ariel_diff {
        writer.write(format!("{}\n", component.to_string()).as_bytes()).expect("failed writing to bufwriter");
    }
    
    writer.write(format!("\nComponents only recognized by {}: {}\n", compared, tool).as_bytes()).expect("failed writing to bufwrite");
    for component in tool_diff {
        writer.write(format!("{}\n", component.to_string()).as_bytes()).expect("failed writing to bufwriter");
    }
}

fn generate_bloat_comparison(intersection: Vec<String>, ariel_diff: Vec<String>, bloat_diff: Vec<String>) {
    
    let file = match File::create(format!("{}ariel_bloat_comparison.txt", RESULT_PATH)) {
        Ok(file) => file,
        Err(e) => panic!("Could not create file {}ariel_bloat_comparison.txt: {}", RESULT_PATH, e)
    };

    let both = intersection.len();
    let ariel = ariel_diff.len();
    let tool = bloat_diff.len();

    let mut writer = BufWriter::new(file);

    writer.write(format!("Components recognized by both tools: {}\n", both).as_bytes()).expect("failed writing to bufwriter");
    for component in intersection {
        writer.write(format!("{}\n", component.to_string()).as_bytes()).expect("failed writing to bufwriter");
    }

    writer.write(format!("\nComponents only recognized by ArielOSBOM: {}\n", ariel).as_bytes()).expect("failed writing to bufwriter");
    for component in ariel_diff {
        writer.write(format!("{}\n", component.to_string()).as_bytes()).expect("failed writing to bufwriter");
    }
    
    writer.write(format!("\nComponents only recognized by bloat: {}\n", tool).as_bytes()).expect("failed writing to bufwrite");
    for component in bloat_diff {
        writer.write(format!("{}\n", component.to_string()).as_bytes()).expect("failed writing to bufwriter");
    }
}

fn generate_bloat_set(file_name: PathBuf) -> BTreeSet<String> {
    
    let file = match File::open(format!("{}{}", RESULT_PATH, file_name.display())) {
        Ok(file) => file,
        Err(e) => panic!("Couldn't open {}: {}", file_name.display(), e)
    };
    
    println!("Reading {}", file_name.display());

    let file_content: Bloat = match serde_json::from_reader(file) {
        Ok(content) => content,
        Err(e) => panic!("Could not extract functions from {}: {}", file_name.display(), e)
    };

    let set: BTreeSet<String> = file_content.functions
                                    .iter()
                                    .map(|function| match &function.crate_name {
                                        Some(name) => name,
                                        None => &function.function_name
                                    }.clone())
                                    .collect();
    return set
}

fn generate_component_set(file_name: PathBuf) -> BTreeSet<String> {
    
    let file = match File::open(format!("{}{}", RESULT_PATH, file_name.display())) {
        Ok(file) => file,
        Err(e) => panic!("Couldn't open {}: {}", file_name.display(), e)
    };
    
    println!("Reading {}", file_name.display());

    let file_content: SBOM = match serde_json::from_reader(file) {
        Ok(content) => content,
        Err(e) => panic!("Could not extract components from {}: {}", file_name.display(), e)
    };

    let set: BTreeSet<String> = file_content.components.iter().map(|component| component.to_string()).collect();
    
    return set
}

fn generate_cargo_bloat(project_path: &str) {

    let file = match File::open(format!("{}build/build-local.ninja", project_path)) {
        Ok(file) => file,
        Err(e) => panic!("Could not open build-local.ninja: {}", e)        
    };

    let reader =BufReader::new(file);
    let mut lines: Vec<String> = vec![];
    for line in reader.lines() {
        match line {
            Ok(content) => lines.push(content),
            Err(_) => panic!("Failed to read build-local.ninja")
        };
    }

    let command_split: Vec<&str> = lines[3].split(" cargo ").collect();

    let current_dir = current_dir().unwrap();

    let (command_left, command_middle, command_right): (&str, &str, &str) = (
        &command_split[0][12..],
        "cargo bloat --full-fn -n 100000 --message-format json",
        &command_split[1].split(" &&").collect::<Vec<&str>>()[0]
    );
    
    //println!("{} {}{} > {}/{}cargo_bloat.json", command_left, command_middle, command_right, current_dir.display(), RESULT_PATH);
    //panic!();
    Command::new("sh")
        .current_dir(project_path)
        .arg("-c")
        .arg(format!("{} {}{} > {}/{}cargo_bloat.json", command_left, command_middle, command_right, current_dir.display(), RESULT_PATH))
        .output()
        .expect("Something failed with cargo_bloat");
    println!("bloat created");

}

fn generate_comparison_sboms(
    project_path: &str, 
    syft_version: &str, 
    crc_version: &str
    ) {

    // Syft
    Command::new(format!("{}syft_{}/syft", TOOL_PATH, syft_version))
        .arg(format!("{}", project_path))
        .arg("-o")
        .arg(format!("cyclonedx-json=syft_{}.json", syft_version))
        .arg("--exclude")
        .arg("./build/imports/**")
        .arg("--source-name")
        .arg("Test")
        .arg("--source-supplier")
        .arg("Test")
        .arg("--source-version")
        .arg("Deez")
        .arg("-q")
        .output()
        .expect("Failed to execute Syft");                        

    // CRC
    Command::new(format!("{}/{}crc_{}/cargo-cyclonedx", current_dir().unwrap().display(), TOOL_PATH, crc_version))
        .current_dir(project_path)
        .arg("cyclonedx")
        .arg("--override-filename")
        .arg(format!("crc_{}", crc_version))
        .arg("-f")
        .arg("json")
        .arg("--spec-version")
        .arg("1.5")
        .output()
        .expect("Failed to execute crc");

        Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("-r")
        .arg(format!("{}", project_path))
        .arg("-o")
        .arg("arielosbom_eval")
        .output()
        .expect("Failed to execute ArielOSBOM");

    // needs a moment so that file can be moved
    // thread::sleep(Duration::from_secs(5));
    Command::new("mv")
        .arg(format!("./syft_{}.json", syft_version))
        .arg(format!("{}", RESULT_PATH))
        .output()
        .expect("Failed to move syft output to results directory");
    Command::new("mv")
        .arg(format!("{}crc_{}.json", project_path, crc_version))
        .arg(format!("{}", RESULT_PATH))
        .output()
        .expect("Failed to move crc output to results directory");
    Command::new("mv")
        .arg("./arielosbom_eval.json")
        .arg(format!("{}", RESULT_PATH))
        .output()
        .expect("Failed to move crc output to results directory");
    //thread::sleep(Duration::from_secs(1));
}