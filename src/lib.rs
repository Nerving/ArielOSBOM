mod build_command;
mod lockfile;
mod component;
pub mod sbom;
mod tree;

use std::{
    path::PathBuf
};

use cargo_metadata::{Error as MetadataError, Metadata, MetadataCommand};

use crate::{
    build_command::{ArielOsBuildCommand, CompileCommandsJson}, 
    sbom::RawSbom, 
    tree::{filter_cargo_metadata, generate_cargo_tree_data},
};


pub struct ArielOsBuildContext {
    root_path: PathBuf,
    manifest_path: PathBuf,
    lock_path: PathBuf,
    import_path: PathBuf,
    build_command: ArielOsBuildCommand,
    builder: String,
}

impl ArielOsBuildContext {

    pub fn from_paths(root_path: &PathBuf, manifest_path: &PathBuf, lock_path: &PathBuf, import_path: &PathBuf, builder: &String) -> ArielOsBuildContext {
        ArielOsBuildContext { 
            root_path: root_path.clone(), 
            manifest_path: manifest_path.clone(), 
            lock_path: lock_path.clone(), 
            import_path: import_path.clone(),
            build_command: ArielOsBuildCommand::default(), 
            builder: builder.clone()
        }
    }

    fn get_build_command(&mut self) {
        match self.builder.to_lowercase().as_str() {
            "none" => {
                println!("no builders specified, using last build command");
                (self.build_command, self.builder) = ArielOsBuildCommand::from_buildlocal(&self.root_path);
            },
            _ => {
                CompileCommandsJson::generate_compile_commands_file(self);
                self.build_command = ArielOsBuildCommand::from_compile_commands_json(&self.root_path);
            }
        };
    }

    pub fn builder(&self) -> &str {
        &self.builder
    }

}

pub fn generate_raw_sbom(context: &mut ArielOsBuildContext) -> RawSbom {

    let mut sbom = RawSbom::default();

    // depending on builder generate or read build command
    context.get_build_command();

    // tree
    let cargo_tree_component_list = generate_cargo_tree_data(&context);

    // metadata
    let cargo_metadata = match generate_cargo_metadata(&context) {
        Ok(metadata) => metadata,
        Err(e) => panic!("error generating cargo metadata:\n{e:?}"),
    };

    // filter metadata
    let filtered_metadata: Metadata = filter_cargo_metadata(&cargo_tree_component_list, cargo_metadata);

    // lock stuff
    let checksum_map = lockfile::generate_checksum_map(&context, cargo_tree_component_list);

    // convert raw shit
    sbom.convert_cargo_data_to_components(&filtered_metadata, checksum_map);

    sbom

}

fn generate_cargo_metadata(context: &ArielOsBuildContext) -> Result<Metadata, MetadataError> {
    let mut metadata_command = MetadataCommand::default();
            metadata_command.current_dir(&context.root_path);
            metadata_command.manifest_path(&context.manifest_path);
            metadata_command.features(cargo_metadata::CargoOpt::SomeFeatures(
                    context.build_command.features
                            .split_once("=").unwrap().1
                            .split(",")
                            .map(|feature| feature.into())
                            .collect()
            ));
    metadata_command.exec()
}