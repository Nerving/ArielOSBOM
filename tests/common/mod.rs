use std::{
    io::Error,
    fs, 
    path::{Path, PathBuf}, 
    process::{Command, Output}
};

use arielosbom::ArielOsBuildContext;


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

#[allow(dead_code)]
pub const STANDARD_EXAMPLE: &'static str = "coap-client";
#[allow(dead_code)]
pub const STANDARD_BUILDER: &'static str = "nrf52840dk";

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
pub fn generate_example_build_context(example_name: &str, builder: &str) -> ArielOsBuildContext {

    ArielOsBuildContext::from_paths(
        &PathBuf::from(CONSTPATHS.ariel_os), 
        &Path::new("examples").join(example_name).join("Cargo.toml"), 
        &PathBuf::from("Cargo.lock"), 
        &PathBuf::from("."), 
        &builder.to_string())

}

#[allow(dead_code)]
pub fn generate_out_of_tree_build_context(builder: &str) -> ArielOsBuildContext {
    ArielOsBuildContext::from_paths(
        &PathBuf::from(CONSTPATHS.out_of_tree), 
        &PathBuf::from("Cargo.toml"), 
        &PathBuf::from("Cargo.lock"), 
        &PathBuf::from("../ariel-os"), 
        &builder.to_string())
}

#[allow(dead_code)]
pub fn generate_build_command_locked(context: &mut ArielOsBuildContext) {

    // locking so that parallel tests don't screw each other up
    let compile_commands_file = std::fs::File::open(context.root_path().join("compile_commands.json")).expect("boohoo");
    _ = compile_commands_file.lock();
    context.get_build_command(None);
    _ = compile_commands_file.unlock();

}

#[allow(dead_code)]
pub fn assert_sbom_generation_status(command_output: Result<Output, Error>, success: bool) {
    
    assert!(
        command_output.is_ok(), 
        "arielosbom execution failed: {:?}", 
        command_output.err()
    );

    let output = command_output.unwrap();

    if success {
        assert!(
            output.status.success(), 
            "SBOM generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        let sbom_path = Path::new(CONSTPATHS.output).join("failure-test_nrf52840dk.1-6.cdx.json");
        let file_exists = sbom_path.exists();
        let file_removed = fs::remove_file(sbom_path);
        assert!(
            !output.status.success(),
            "SBOM generation did not fail \nSBOM file located: {}\nSBOM file removed: {}",
            file_exists, file_removed.is_ok()
        );
    }
}

pub fn create_env_tuples(names: Vec<&str>) -> Vec<(&str, &str)> {
    names.iter().map(|name| (*name, "1")).collect()
}

#[allow(dead_code)]
pub fn create_e2e_envs() -> Vec<(&'static str, &'static str)> {
    create_env_tuples(vec![TESTENVS.testing])
}