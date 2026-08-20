mod cliarg;

use std::fs::create_dir;

use arielosbom::{ArielOsBuildContext, OutputConfiguration, generate_raw_sbom};
use clap::Parser;

use crate::cliarg::Args;

fn main() {
    let cli_args = Args::parse();

    if !(cli_args.project_root_path.exists()) {
        panic!(
            "Cannot find project root path:\n{:?}",
            cli_args.project_root_path
        );
    }

    if !(cli_args.output_dir.exists()) {
        match create_dir(&cli_args.output_dir) {
            Ok(_) => println!(
                "created output directory: {}\n",
                cli_args.output_dir.canonicalize().unwrap().display()
            ),
            Err(e) => panic!("failed to created output directory: {:?}\n", e),
        };
    }

    let output_config = Some(OutputConfiguration::new(
        cli_args.output_name.clone(),
        cli_args.output_dir.clone(),
        cli_args.bom_formats.clone(),
    ));

    for builder in &cli_args.builders {
        let mut build_context = ArielOsBuildContext::from_paths(
            &cli_args.project_root_path,
            &cli_args.project_manifest_path,
            &cli_args.project_lock_path,
            &cli_args.arielos_import_path,
            builder,
        );

        //let mut generator_output =
        generate_raw_sbom(
            &mut build_context,
            &output_config,
            cli_args.emit_cargo_artifacts,
        );
    }
}
