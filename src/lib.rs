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

use cargo_lock::{Package as LockPackage, SourceId};
use cargo_metadata::{Error as MetadataError, Metadata, MetadataCommand};
use semver::Version;

use crate::{
    build_command::{ArielOsBuildCommand, CompileCommandsJson},
    sbom::{FileFormat, RawSbom},
    tree::{generate_cargo_tree_output, parse_cargo_tree},
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

// #[derive(Clone, PartialEq, Eq, Hash, Debug)]
// pub struct CrateIdentifier {
//     name: String,
//     version: Version,
// }

// impl CrateIdentifier {
//     pub fn new(name: String, version: Version) -> Self {
//         CrateIdentifier { name, version }
//     }

//     pub fn name(&self) -> &str {
//         &self.name
//     }
// }

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CrateId {
    name: String,
    version: Version,
    source: CrateSource,
}

impl CrateId {
    fn new(name: String, version: Version, source: CrateSource) -> Self {
        CrateId {
            name,
            version,
            source,
        }
    }

    pub fn from_package_id(package_id: &str) -> Self {
        let name;
        let version;
        let source;

        let (source_type, source_content) = package_id.split_once('+').unwrap();

        match source_type {
            "registry" => {
                let name_and_version = source_content
                    .split_once('#')
                    .unwrap()
                    .1
                    .split_once('@')
                    .unwrap();
                name = name_and_version.0.to_string();
                version = Version::parse(name_and_version.1).unwrap();
                source = CrateSource::CratesIo;
            }
            "git" => {
                (name, version, source) =
                    CrateSource::parse_git_or_path(package_id, source_content, true);
            }
            "path" => {
                (name, version, source) =
                    CrateSource::parse_git_or_path(package_id, source_content, false);
            }
            _ => panic!("unknown package id start: {}", source_type),
        }

        CrateId {
            name,
            version,
            source,
        }
    }

    pub fn from_cargo_tree_line(line: &str) -> (Self, bool) {
        let end_trimmed = line.trim_end_matches(" (*)");
        let mut split_line = end_trimmed.split_whitespace();

        //we are guaranteed to have name and version; would technically want to check for errors though
        let name = split_line.next().unwrap().to_string();
        let version = Version::parse(&split_line.next().unwrap()[1..]).unwrap();

        let mut is_proc_macro = false;
        let mut source = CrateSource::CratesIo;
        for part in split_line {
            if part == "(proc-macro)" {
                is_proc_macro = true;
            } else {
                // based on the parameters supplied to cargo tree, there cannot be any other inforamtion
                source = CrateSource::from_cargo_tree_source(&part[1..part.len() - 1]);
            }
        }

        (CrateId::new(name, version, source), is_proc_macro)
    }

    fn from_lockfile_package(lockfile_package: &LockPackage) -> Self {
        CrateId::new(
            lockfile_package.name.to_string(),
            lockfile_package.version.clone(),
            CrateSource::from_lockfile_source(&lockfile_package.source),
        )
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum CrateSource {
    CratesIo,
    External(String),
    Local(PathBuf),
    LocalNoPath,
}

impl CrateSource {
    fn from_cargo_tree_source(source_info: &str) -> Self {
        if source_info.starts_with("https") {
            CrateSource::External(source_info.rsplit_once('#').unwrap().0.to_string())
        } else {
            CrateSource::Local(Path::new(source_info).to_path_buf())
        }
    }

    // requires extension for potential other sources that may appear; only registry/external/local path right now
    fn from_lockfile_source(source_id: &Option<SourceId>) -> Self {
        if let Some(source) = source_id {
            if source.is_default_registry() {
                Self::CratesIo
            } else if source.is_git() {
                Self::External(source.to_string().rsplit_once('+').unwrap().1.to_string())
            } else {
                panic!("unexpected source kind");
            }
        } else {
            Self::LocalNoPath
        }
    }

    fn parse_git_or_path(
        package_id: &str,
        source_content: &str,
        git: bool,
    ) -> (String, Version, Self) {
        let name_and_version = if !source_content.contains('@') {
            source_content
                .rsplit_once('/')
                .unwrap()
                .1
                .rsplit_once('#')
                .unwrap()
        } else {
            source_content
                .rsplit_once('#')
                .unwrap()
                .1
                .rsplit_once('@')
                .unwrap()
        };
        let mut name = name_and_version.0.to_string();
        // for git sources such as
        // git+https://github.com/ariel-os/esp-hal?rev=531c629afdd80ea464682ce7f4db8baed97967a6#1.0.0
        if name.contains('?') {
            name = name.split_once('?').unwrap().0.to_string();
        }

        let version = Version::parse(name_and_version.1).unwrap();
        let source = match git {
            true => CrateSource::External(
                package_id
                    .trim_start_matches("git+")
                    .rsplit_once('#')
                    .unwrap()
                    .0
                    .into(),
            ),
            false => CrateSource::Local(
                package_id
                    .trim_start_matches("path+file://")
                    .rsplit_once('#')
                    .unwrap()
                    .0
                    .into(),
            ),
        };

        (name, version, source)
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
    let parsed_tree = parse_cargo_tree(cargo_tree_data);

    let cargo_metadata = match generate_cargo_metadata(context) {
        Ok(metadata) => metadata,
        Err(e) => panic!("error generating cargo metadata:\n{e:?}"),
    };
    let original_metadata = if emit_cargo_artifacts {
        Some(cargo_metadata.clone())
    } else {
        None
    };

    let checksum_map = lockfile::generate_checksum_map(context); //, &parsed_tree);

    sbom.convert_cargo_data_to_components(&cargo_metadata, checksum_map, parsed_tree);

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
