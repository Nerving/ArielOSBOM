use std::{
    io::Error,
    fs, 
    path::Path, 
    process::{Command, Output}
};


#[allow(dead_code)]
pub struct ConstPaths {
    pub ariel_os: &'static str,
    pub out_of_tree: &'static str,
    pub output: &'static str,
    pub schemata: &'static str,
    
}

#[allow(dead_code)]
pub struct TestEnvs {
    pub testing: &'static str,
    pub deterministic: &'static str,
}

pub const CONSTPATHS: ConstPaths = ConstPaths {
    ariel_os: "tests/fixtures/ariel-os",
    out_of_tree: "tests/fixtures/out-of-tree-coap-client",
    output: "tests/output",
    schemata: "tests/fixtures/schemata",
};

pub const TESTENVS: TestEnvs = TestEnvs {
    testing: "TESTING",
    deterministic: "TESTING_DETERMINISTIC"
};

pub fn check_environment() {

    if !(Path::new(CONSTPATHS.ariel_os).exists()) {
        Command::new("git")
            .arg("clone")
            .arg("https://github.com/ariel-os/ariel-os.git")
            .arg(CONSTPATHS.ariel_os)
            .output()
            .expect("Failed to import Ariel OS repo");
    }
    assert!(Path::new(CONSTPATHS.ariel_os).exists());

    if !(Path::new(CONSTPATHS.output).exists()) {
        match fs::create_dir(CONSTPATHS.output) {
            Ok(_) => println!("created output directory: {}\n", CONSTPATHS.output),
            Err(e) => panic!("failed to created output directory: {:?}\n", e)
        };
    }
    assert!(Path::new(CONSTPATHS.output).exists());
}

#[allow(dead_code)]
pub fn parse_sbom(path: &Path, error_message: &str) -> serde_json::Value {
    
    let sbom_file = fs::File::open(path)
        .expect(&format!("failed to open {} SBOM", error_message));

    serde_json::from_reader(sbom_file)
        .expect(&format!("failed to parse {} SBOM", error_message))

}

#[allow(dead_code)]
pub fn test_binary(
    envs: Option<Vec<(&str, &str)>>,
    project_path: &Path, 
    bom_formats: &Vec<&str>,
    builders: Option<Vec<&str>>,
    output_name: &str,
    //output_directory: fixed no?
    manifest_path: Option<&Path>,
    lock_path: Option<&Path>,
    import_path: Option<&Path>,
) -> Result<Output, Error> {

    let sbom_generation = Command::new(env!("CARGO_BIN_EXE_arielosbom"))
        .envs(envs.unwrap_or(vec![]))
        .arg("-r").arg(project_path)
        .arg("-m").arg(manifest_path.unwrap_or(Path::new("Cargo.toml")))
        .arg("-b").args(bom_formats)
        .arg("--builders").args(builders.unwrap_or(vec!["none"]))
        .arg("-o").arg(output_name)
        .arg("--output-directory").arg(Path::new(CONSTPATHS.output))
        .arg("-l").arg(lock_path.unwrap_or(Path::new("Cargo.lock")))
        .arg("-i").arg(import_path.unwrap_or(Path::new("build/imports/ariel-os")))
        .output();

    sbom_generation
}

#[allow(dead_code)]
pub fn assert_sbom_generation_status(command_output: Result<Output, Error>) {
    
    assert!(
        command_output.is_ok(), 
        "arielosbom execution failed: {:?}", 
        command_output.err()
    );

    let output = command_output.unwrap();

    assert!(
        output.status.success(), 
        "SBOM generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn create_env_tuples(names: Vec<&str>) -> Vec<(&str, &str)> {
    names.iter().map(|name| (*name, "1")).collect()
}

#[allow(dead_code)]
pub fn create_e2e_envs() -> Vec<(&'static str, &'static str)> {
    create_env_tuples(vec![TESTENVS.testing])
}