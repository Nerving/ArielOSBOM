A build-level SBOM generator for Ariel OS based Rust projects.

## Motivation and Goals

With increasing software supply chain attacks and security demands, Software Bills of Materials (SBOMs) have gained relevance in recent years. In the EU, the [Cyber Resilience Act (CRA)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) will be requiring suppliers to draw up and if necessary provide SBOMs for their software. As a FOSS project, Ariel OS itself technically does not fall under the CRA, however as seen with [RIOT e.g.](https://github.com/RIOT-OS/RIOT/pull/21530) demand can exist for users of Ariel OS, so providing tooling to support with that makes sense. 

The goal of this project is to create/lay the groundwork for an SBOM generator for [Ariel OS](https://github.com/ariel-os/ariel-os) projects. Since the CRA does not go into much detail in terms of SBOM requirements, right now the current [BSI technical guideline for SBOMs](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf) will instead be used as a reference and compliance for it be strived towards.

## Current state

Generates an SBOM of an Ariel OS project at the scope of the specified boards or last executed build as documented in `<PATH_TO_PROJECT>/build/build-local.ninja`, providing information for all Rust components that were compiled during the build process. 

As of now the tool does the following:
- if provided, generate build files for the specified board(s)
- extract build information from the last laze build command
- generate cargo-tree data for component baseline
- run cargo metadata for info crate metadata
- filter only the crates listed by cargo tree
- take available relevant information from (filtered) cargo metadata
- write output to file, in "raw format" for own further use or as Cyclone-DX (version 1.6/1.7); no SPDX so far

### What the tool currently does provide

- build-level component recognition
    - Rust components
        - catalogues only all crates that are compiled during the building process
        - takes features and environment variables into account
    - information on
        - component dependencies (in the build-specific context)
        - name, version, license(s)\*, creator(s)\*, source repository link\*
        - crate hashes via Cargo.lock if provided via crates.io
- SBOM generation
    - at the project root level and also for other workspace members (e. g. tests/examples)
    - based on the specified builders or the last executed build command
    - output formats
        - raw data format that is used during component aggregation
        - CycloneDX version 1.6, 1.7 (due to the limited fields, they are basically identical right now) 

### What the tool currently does not provide (yet)

- build-level component recognition
    - no component recognition outside of Rust/Cargo context
    - no alternative processing if cargo metadata fails, e.g. when not running in nightly context
    - information marked with \* in the previous section if it is not provided by cargo metadata
    - information on
        - license information from LICENSE file(s) if present
        - crate features
        - additional component identifiers (purl, cpe, SWHID, ...)
- program metadata
    - intended device specifications, storage/memory footprint, supported features/protocls, ... (suggestions?)
- SBOM generation
    - output formats
        - any SPDX version
        - older CycloneDX versions
- (full BSI guideline compliance?)

## Usage

### Installation

- simply clone this repository to a location of your choosing
- install the [build prerequisites](https://ariel-os.github.io/ariel-os/dev/docs/book/getting-started.html#installing-the-build-prerequisites) needed for Ariel OS
- if not done already, install nightly toolchain: `rustup toolchain install nightly`

### Execution

- only works using nightly toolchain right now (otherwise cargo metadata fails for Ariel OS projects)

Option 1:
- provide the project's root path via the command line (`-r <PATH>`)
- provide the laze builder(s) for which you want to generate the SBOM(s) via the command line (`--builders <BUILDERS>`)
- provide other arguments as desired/necessary

Option 2:
- run the build process for which you want to generate the SBOM first (program takes latest command from ./builds/build-local.ninja)
- provide the project's root path via the command line (`-r <PATH>`)
- provide other arguments as desired/necessary

Current cli arguments:
```
    -r, --root-path <PATH>
        Path to project root
        
        [default: ./]

    -b, --bom-formats <BOM_FORMAT>...
            BOM formats to generate (space separated)
            Possible values (case-insensitive):
                - raw:			            output of the raw aggregated information
                - spdx:			            no SPDX support currently
                - cdx_1.6/cyclonedx_1.6:	CycloneDX version 1.6
                - cdx_1.7/cyclonedx_1.7:    CycloneDX version 1.7
            
            [default: raw]

    -f, --file-format <FILE_EXTENSION>
            File format of the generated SBOM
            Possible values (case-insensitive):
                -json
            
            [default: json]

        --builders <BUILDERS>
            Laze builder targets (max 16, space separated) to generate SBOMs for; if not provided, uses last build command

            [default: none]

    -o, --output-name <FILE_NAME>
            File name of the generated SBOM(s)
            Depending on the builder and the SBOM format, the full file name will be <FILE_NAME>_<BUILDER>.<BOM_FORMAT>.<FILE_EXTENSION>
            
            [default: arielosbom]

    -m, --manifest-path <PATH>
            Path to the build's manifest file relative to its root
            
            [default: ./Cargo.toml]

    -l, --lock-path <PATH>
            Path to the project's lock file relative to its root
            
            [default: ./Cargo.lock]

    -i, --import-path <PATH>
            Path to the project's ArielOS import directory relative to its root
            
            [default: ./build/imports/ariel-os/]

    -h, --help
            Print help (see a summary with '-h')
```

### Example (out-of-tree Ariel OS project, with --builders argument)

Installation + Setup:
- Clone this repo to a location of your choosing: 

`git clone https://github.com/Nerving/ArielOSBOM.git`

- Install nightly toolchain if needed and set it as default:

`rustup toolchain install nightly`, `rustup default nightly`

- Have your own project [set up from a template repository](https://ariel-os.github.io/ariel-os/dev/docs/book/getting-started.html#starting-an-application-project-from-a-template-repository)

Execution:

- Run ArielOSBOM (where its repo was cloned to) with your project root path and your desired builders as cli arguments.

`cargo run -- -r <PATH> --builders <BUILDER1> <BUILDER2> ...`

- The output file will be put into the the ./output directory.

---

### Example (out-of-tree Ariel OS project, without --builders argument)

Installation + Setup:

- same as the previous example

Execution:
- Run the build for your project at your project's root directory:

`laze build -b <BUILDER>`

- Run ArielOSBOM (where its repo was cloned to) with your project root path ~~and your desired builders~~ as cli argument~~s~~.

`cargo run -- -r <PATH> `~~`--builders <BUILDER1> <BUILDER2> ...`~~

- The output file will be put into the the ./output directory.

---

### Example (Ariel OS Coap Test, non-project-root, with --builders argument)

Installation + Setup:
- as before except:

- ~~Have your own project set up from a template repository~~ Clone the ArielOS main repo:

`git clone https://github.com/ariel-os/ariel-os.git`

Execution:

- Run ArielOSBOM (where its repo was cloned to) with your project root path, the relative path to the test case's Cargo.toml, because it is not in the root directory, and your desired builders as cli arguments. Since we are in the original ArielOS repository, we do not have an import, so we only have the lock file at the root:

`cargo run -- -r <PATH> -m ./tests/coap/Cargo.toml --import-path ./ --builders <BUILDER1> <BUILDER2> ...`

---

### Example (Ariel OS Coap Test, non-project-root, without --builders argument)

Installation + Setup:

- same as the last example

Execution:

- Run the build for /tests/coap/ in the ArielOS repo root:

`laze -C tests/coap build -b <board>`
- Run ArielOSBOM (where its repo was cloned to) with your project root path and the relative path to the test case's Cargo.toml, because it is not in the root directory, as cli arguments. Since we are in the original ArielOS repository, we do not have an import, so we only have the lock file at the root:

`cargo run -- -r <PATH> -m ./tests/coap/Cargo.toml --import-path ./`

- The output file will be put into the ./output directory.

---

## Contact

For feedback of any sorts, I can also be messaged on Matrix: @lekilian:matrix.org

--- 

This repository is for the WIP project for my bachelor's thesis (Comp. Sci., FU Berlin) under the guidance of [Prof. Dr. Emmanuel Baccelli](https://emmanuelbaccelli.com/). 