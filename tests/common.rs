use std::{
    io::Error,
    fs, 
    path::{Path, PathBuf}, 
    process::{Command, Output}
};

#[allow(dead_code)]
pub struct ConstPaths {
    pub ariel_os: &'static str,
    pub schemata: &'static str,
    pub output: &'static str,
}

pub const CONSTPATHS: ConstPaths = ConstPaths {
    ariel_os: "tests/fixtures/ariel-os",
    schemata: "tests/fixtures/schemata",
    output: "tests/output",
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

pub fn generate_test_sbom(
    envs: Option<Vec<(&str, &str)>>,
    project_path: &Path, 
    bom_formats: &Vec<&str>,
    builders: Option<Vec<&str>>,
    output_name: &str,
    //output_directory: fixed no?
    manifest_path: PathBuf,
    lock_path: Option<&Path>,
    import_path: &Path,
) -> Result<Output, Error> {

    let sbom_generation = Command::new(env!("CARGO_BIN_EXE_arielosbom"))
        .envs(envs.unwrap_or(vec![]))
        .arg("-r").arg(project_path)
        .arg("-m").arg(manifest_path)
        .arg("-b").args(bom_formats)
        .arg("--builders").args(builders.unwrap_or(vec!["none"]))
        .arg("-o").arg(output_name)
        .arg("--output-directory").arg(Path::new(CONSTPATHS.output))
        .arg("-l").arg(lock_path.unwrap_or(Path::new("Cargo.lock")))
        .arg("-i").arg(import_path)
        .output();

    sbom_generation
}

pub fn assert_sbom_generation_status(command_output: Output) {
    assert!(
        if let Some(code) = command_output.status.code() {code == 0} else {false}, 
        "SBOM generation failed: {}",
        String::from_utf8_lossy(&command_output.stderr)
    );
}