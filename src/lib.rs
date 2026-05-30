pub mod build_command;
mod component;
mod lockfile;
pub mod sbom;
pub mod tree;

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use cargo_metadata::{Error as MetadataError, Metadata, MetadataCommand};

use crate::{
    build_command::{ArielOsBuildCommand, CompileCommandsJson},
    sbom::{FileFormat, RawSbom},
    tree::{filter_cargo_metadata, generate_cargo_tree_component_list, generate_cargo_tree_output},
};

pub struct ArielOsBuildContext {
    root_path: PathBuf,
    manifest_path: PathBuf,
    lock_path: PathBuf,
    import_path: PathBuf,
    pub build_command: ArielOsBuildCommand,
    builder: String,
}

impl ArielOsBuildContext {
    pub fn from_paths(
        root_path: &Path,
        manifest_path: &Path,
        lock_path: &Path,
        import_path: &Path,
        builder: &str,
    ) -> ArielOsBuildContext {
        ArielOsBuildContext {
            root_path: root_path.to_path_buf(),
            manifest_path: manifest_path.to_path_buf(),
            lock_path: lock_path.to_path_buf(),
            import_path: import_path.to_path_buf(),
            build_command: ArielOsBuildCommand::default(),
            builder: builder.to_owned(),
        }
    }

    pub fn get_build_command(&mut self, compile_commands_directory: Option<&Path>) {
        match self.builder.to_lowercase().as_str() {
            "none" => {
                println!("no builders specified, using last build command");
                (self.build_command, self.builder) =
                    ArielOsBuildCommand::from_buildlocal(&self.root_path);
            }
            _ => {
                if let Some(path) = compile_commands_directory {
                    self.build_command = ArielOsBuildCommand::from_compile_commands_json(path);
                } else {
                    CompileCommandsJson::generate_compile_commands_file(self);
                    self.build_command =
                        ArielOsBuildCommand::from_compile_commands_json(&self.root_path);
                }
            }
        };
    }
}

pub struct GeneratorOutput {
    pub sbom: RawSbom,
    pub metadata: Option<Metadata>,
    pub tree: Option<Vec<u8>>,
}

pub fn generate_raw_sbom(
    context: &mut ArielOsBuildContext,
    emit_cargo_artifacts: bool,
) -> GeneratorOutput {
    let mut sbom = RawSbom::empty();

    if context.build_command == ArielOsBuildCommand::default() {
        context.get_build_command(None);
    }

    let cargo_tree_data = generate_cargo_tree_output(context);
    let original_cargo_tree = if emit_cargo_artifacts {
        Some(cargo_tree_data.clone())
    } else {
        None
    };
    let cargo_tree_component_list = generate_cargo_tree_component_list(cargo_tree_data);

    let cargo_metadata = match generate_cargo_metadata(context) {
        Ok(metadata) => metadata,
        Err(e) => panic!("error generating cargo metadata:\n{e:?}"),
    };
    let original_metadata = if emit_cargo_artifacts {
        Some(cargo_metadata.clone())
    } else {
        None
    };

    let filtered_metadata: Metadata =
        filter_cargo_metadata(&cargo_tree_component_list, cargo_metadata);

    let checksum_map = lockfile::generate_checksum_map(context, cargo_tree_component_list);

    sbom.convert_cargo_data_to_components(&filtered_metadata, checksum_map);

    GeneratorOutput {
        sbom,
        metadata: original_metadata,
        tree: original_cargo_tree,
    }
}

fn generate_cargo_metadata(context: &ArielOsBuildContext) -> Result<Metadata, MetadataError> {
    let mut metadata_command = MetadataCommand::default();
    metadata_command.current_dir(&context.root_path);
    metadata_command.manifest_path(&context.manifest_path);
    metadata_command.features(cargo_metadata::CargoOpt::SomeFeatures(
        context
            .build_command
            .features
            .split_once("=")
            .unwrap()
            .1
            .split(",")
            .map(|feature| feature.into())
            .collect(),
    ));
    metadata_command.exec()
}

pub fn write_metadata_to_file(
    metadata: Metadata,
    file_name: &str,
    output_dir: &Path,
    builder: &str,
) {
    let file_format = FileFormat::Json;
    let full_file_name = format!("{}_{}.metadata.{}", file_name, builder, file_format);
    let mut file = match File::create(Path::new(output_dir).join(&full_file_name)) {
        Ok(file) => file,
        Err(e) => panic!("Could not create file: {}: {}", full_file_name, e),
    };

    file.write_all(
        &serde_json::to_vec_pretty(&metadata).expect("failed to serialize cargo metadata"),
    )
    .expect("failed to write cargo metadata to file");
}

impl ArielOsBuildContext {
    pub fn root_path(&self) -> &PathBuf {
        &self.root_path
    }

    pub fn manifest_path(&self) -> &PathBuf {
        &self.manifest_path
    }

    pub fn lock_path(&self) -> &PathBuf {
        &self.lock_path
    }

    pub fn import_path(&self) -> &PathBuf {
        &self.import_path
    }

    pub fn build_command(&self) -> &ArielOsBuildCommand {
        &self.build_command
    }

    pub fn builder(&self) -> &str {
        &self.builder
    }
}
