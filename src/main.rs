mod cliarg;

use std::{
        fs::create_dir, 
};

use arielosbom::{
    ArielOsBuildContext, 
    generate_raw_sbom,
    tree::write_tree_to_file,
    write_metadata_to_file,
};
use clap::{Parser};

use crate::cliarg::Args;


fn main() {
    let cli_args = Args::parse();

    if !(cli_args.project_root_path.exists()) { panic!("Cannot find project root path:\n{:?}", cli_args.project_root_path); }

    if !(cli_args.output_dir.exists()) {
        match create_dir(&cli_args.output_dir) {
            Ok(_) => println!("created output directory: {}\n", cli_args.output_dir.canonicalize().unwrap().display()),
            Err(e) => panic!("failed to created output directory: {:?}\n", e)
        };
    }

    // future: do not generate each sbom entirely seperately but fill "database" of components first and then generate all boms accordingly
        
    for builder in &cli_args.builders {
        
        let mut build_context = ArielOsBuildContext::from_paths(
            &cli_args.project_root_path,
            &cli_args.project_manifest_path,
            &cli_args.project_lock_path,
            &cli_args.arielos_import_path,
            builder
        );

        let mut generator_output = generate_raw_sbom(&mut build_context, cli_args.emit_cargo_artifacts);

        if cli_args.emit_cargo_artifacts {
            write_tree_to_file(generator_output.tree.unwrap(), &cli_args.output_name, &cli_args.output_dir, build_context.builder());
            write_metadata_to_file(generator_output.metadata.unwrap(), &cli_args.output_name, &cli_args.output_dir, build_context.builder());
        }

        for bom_format in &cli_args.bom_formats {
            arielosbom::sbom::write_sbom_to_file(&mut generator_output.sbom, bom_format, &cli_args.output_name, &cli_args.output_dir, build_context.builder());
        }
    }
}

