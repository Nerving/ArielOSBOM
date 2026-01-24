//mod bloat;
mod component;
mod cliarg;
mod sbom;
mod tree;

use crate::{
        cliarg::{Args},
        sbom::{SBOM, BomFormat},
        tree::{generate_cargo_tree_data},
};

use cargo_lock::{Lockfile, Error as LockError};
use cargo_metadata::{Error as MetadataError, Metadata, MetadataCommand};
use clap::{Parser};

use std::path::{Path};



// add build command extraction here

fn generate_cargo_metadata(root_path: &Path, manifest_path: &Path) -> Result<Metadata, MetadataError> {
        let mut metadata_command = MetadataCommand::default();
                metadata_command.current_dir(root_path);
                metadata_command.manifest_path(manifest_path);
        // more for features/otheroptions in the future
        metadata_command.exec()
}

fn generate_carg_lock_data(lock_path: &Path) -> Result<Lockfile, LockError> {
        Lockfile::load(lock_path)
}


fn main() {

        let cli_args = Args::parse();

        if !(cli_args.project_root_path.exists()) { panic!("Cannot find project root path:\n{:?}", cli_args.project_root_path); }
        
        // TODO: handle stuff that might have to be handled first by CLI arguments
                // e.g. setting up logging; or "environment" for/if SBOMs to be created

        // just one for now, potentially for different devices in the future
        let mut sboms = SBOM::new(BomFormat::Raw);

        let tree_data = generate_cargo_tree_data(&cli_args.project_root_path);

        // will need error handling in case metadata fails -> manual data gathering then?
        let metadata = match generate_cargo_metadata(&cli_args.project_root_path, &cli_args.project_manifest_path) { 
                Ok(metadata) => metadata,
                Err(e) => panic!("Error generating cargo metadata:\n{e:?}"),
        };

        let lock_data = match generate_carg_lock_data(&cli_args.project_lock_path) {
                Ok(lock_data) => lock_data,
                Err(e)=> panic!("Error loading Cargo.lock data:\n{e:?}"),
        };

        // filtering for: only crates that were actually compiled

        let filtered_metadata: Metadata = tree::filter_cargo_metadata(tree_data, metadata);

        println!("packages: {}, dependencies: {}", filtered_metadata.packages.len(), filtered_metadata.resolve.as_ref().unwrap().nodes.len());

        // extract information from cargo metadata
        sboms.convert_cargo_metadata_packages_to_components(&filtered_metadata, &lock_data);

        // TODO:
                // complete missing info
                // non-Metadata/-Rust stuff

        sboms.write_to_file(&cli_args.output_name);

}

