use std::{collections::HashMap, path::Path};

use cargo_lock::{Checksum, Error as LockError, Lockfile};

use crate::{ArielOsBuildContext, CrateId};

pub fn generate_checksum_map(
    context: &ArielOsBuildContext,
    //tree_graph: &CargoTreeGraph,
) -> HashMap<CrateId, Checksum> {
    let root_lock_data = match read_lockfile(&context.root_path, &context.lock_path) {
        Ok(lock_data) => lock_data,
        Err(e) => panic!("error loading Cargo.lock data:\n{e:?}"),
    };
    let import_lock_data =
        match read_lockfile(&context.root_path, &context.import_path.join("Cargo.lock")) {
            Ok(lock_data) => lock_data,
            Err(e) => panic!("error loading ArielOS import Cargo.lock data:\n{e:?}"),
        };

    HashMap::from_iter(
        root_lock_data
            .packages
            .iter()
            .chain(import_lock_data.packages.iter())
            .filter(|package| package.checksum.is_some())
            .map(|package| {
                (
                    CrateId::from_lockfile_package(package),
                    package.checksum.clone().unwrap(),
                )
            }),
    )
}

fn read_lockfile(root_path: &Path, lock_path: &Path) -> Result<Lockfile, LockError> {
    Lockfile::load(Path::new(root_path).join(lock_path))
}
