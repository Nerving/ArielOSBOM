use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use cargo_lock::{Checksum, Error as LockError, Lockfile, Package as LockPackage};

use crate::{ArielOsBuildContext, CrateIdentifier, tree::CargoTreeGraph};

pub fn generate_checksum_map(
    context: &ArielOsBuildContext,
    tree_graph: &CargoTreeGraph,
) -> HashMap<CrateIdentifier, Checksum> {
    let root_lock_data = match read_lockfile(&context.root_path, &context.lock_path) {
        Ok(lock_data) => lock_data,
        Err(e) => panic!("error loading Cargo.lock data:\n{e:?}"),
    };
    let import_lock_data =
        match read_lockfile(&context.root_path, &context.import_path.join("Cargo.lock")) {
            Ok(lock_data) => lock_data,
            Err(e) => panic!("error loading ArielOS import Cargo.lock data:\n{e:?}"),
        };

    let enriched_lockfile = enrich_lockfile(root_lock_data, import_lock_data, tree_graph);

    HashMap::from_iter(
        enriched_lockfile
            .packages
            .iter()
            .filter(|lock_package| lock_package.checksum.is_some())
            .map(|lock_package| {
                (
                    CrateIdentifier::new(
                        lock_package.name.to_string(),
                        lock_package.version.clone(),
                    ),
                    lock_package.checksum.clone().unwrap(),
                )
            }),
    )
}

fn read_lockfile(root_path: &Path, lock_path: &Path) -> Result<Lockfile, LockError> {
    Lockfile::load(Path::new(root_path).join(lock_path))
}

fn enrich_lockfile(
    mut main_lockfile: Lockfile,
    secondary_lockfile: Lockfile,
    tree_graph: &CargoTreeGraph,
) -> Lockfile {
    let main_lockfile_package_set: HashSet<CrateIdentifier> = main_lockfile
        .packages
        .iter()
        .map(|package| CrateIdentifier::new(package.name.to_string(), package.version.clone()))
        .collect();

    let missing_checksum_list: HashSet<&CrateIdentifier> = HashSet::from_iter(
        tree_graph
            .nodes
            .iter()
            .filter(|entry| !main_lockfile_package_set.contains(entry.identifier()))
            .map(|entry| entry.identifier()),
    );

    main_lockfile
        .packages
        .append(&mut extract_missing_checksums(
            missing_checksum_list,
            secondary_lockfile.packages,
        ));

    main_lockfile
}

fn extract_missing_checksums(
    checklist: HashSet<&CrateIdentifier>,
    import_lockdata: Vec<LockPackage>,
) -> Vec<LockPackage> {
    import_lockdata
        .into_iter()
        .filter(|package| {
            checklist.contains(&CrateIdentifier::new(
                package.name.to_string(),
                package.version.clone(),
            ))
        })
        .collect::<Vec<LockPackage>>()
}
