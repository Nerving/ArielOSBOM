This repository is for the WIP project for my bachelor's thesis (Comp. Sci., FU Berlin) under the guidance of [Prof. Dr. Emmanuel Baccelli](https://emmanuelbaccelli.com/). 

## Motivation and Goals

With increasing software supply chain attacks and security demands, Software Bills of Materials (SBOMs) have gained relevance in recent years. In the EU, the [Cyber Resilience Act (CRA)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) will be requiring suppliers to draw up and if necessary provide SBOMs for their software. As a FOSS project, ArielOS itself technically does not fall under the CRA, however as seen with [RIOT e.g.](https://github.com/RIOT-OS/RIOT/pull/21530) demand can exist for users of ArielOS, so providing tooling to support with that makes sense. 

The goal of this project is to create/lay the groundwork for an SBOM generator for [Ariel OS](https://github.com/ariel-os/ariel-os) projects. Since the CRA does not go into much detail in terms of SBOM requirements, right now the current [BSI technical guideline for SBOMs](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf) will instead be used as a reference and compliance for it be strived towards.

## Current state

Generates an SBOM of an ArielOS project at the scope of the last executed build as documented in `<PATH_TO_PROJECT>/build/build-local.ninja`, providing information for all Rust components that were compiled during the build process. 

As of now the tool does the following:
- extract build information from the last laze build command
- generate cargo-tree data for component baseline
- run cargo metadata for info crate metadata
- filter only the crates listed by cargo tree
- take available relevant information from (filtered) cargo metadata
- write output to file, in "raw format" for own further use or as Cyclone-DX (currently only version 1.7); no SPDX so far

## Usage

### Installation

- simply clone this repository to a location of your choosing
- install the [build prerequisites](https://ariel-os.github.io/ariel-os/dev/docs/book/getting-started.html#installing-the-build-prerequisites) needed for ArielOS
- if not done already, install nightly toolchain: `rustup toolchain install nightly`

### Execution

- run the build process for which you want to generate the SBOM first (program takes latest command from ./builds/build-local.ninja) 
- only works using nightly toolchain right now (otherwise cargo metadata fails for ArielOS projects)
- provide the project's root path via the command line (`-r <PATH>`)
- provide after arguments as desired/necessary

Current cli arguments:
```
    -r, --root-path <PATH>
        Path to project root
        
        [default: ./]

    -b, --bom-formats <BOM_FORMAT>...
            BOM formats to generate (space separated)
            Possible values (case-insensitive):
                - raw:			output of the raw aggregated information
                - spdx:			no SPDX support currently
                - cdx/cyclonedx/cyclone-dx:	CycloneDX version 1.7
            
            [default: raw]

    -f, --file-format <FILE_EXTENSION>
            File format of the generated SBOM
            Possible values (case-insensitive):
                -json
            
            [default: json]

    -o, --output-name <FILE_NAME>
            File name of the generated SBOM(s)
            Depending on the chosen SBOM format, the full file name will be <FILE_NAME>.<BOM_FORMAT>.<FILE_EXTENSION>
            
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
### Example (out-of-tree ArielOS projects)

Installation + Setup:
- Clone the repo to a location of your choosing: 

`git clone https://github.com/Nerving/ArielOSBOM.git`

- Install nightly toolchain if needed and set it as default:

`rustup toolchain install nightly`, `rustup default nightly`

- Have your own project [set up from a template repository](https://ariel-os.github.io/ariel-os/dev/docs/book/getting-started.html#starting-an-application-project-from-a-template-repository)

Execution:
- Run the build for your project at your project's root directory:

`laze build -b <board>`

- Run ArielOSBOM (where its repo was cloned to) with your project root path as cli argument.

`cargo run -- -r <PATH>`

- The output file will be put into the the ./output directory.

### Example (ArielOS Coap Test, non-project-root)

Installation + Setup:
- as before except:

- ~~Have your own project set up from a template repository~~ Clone the ArielOS main repo:

`git clone https://github.com/ariel-os/ariel-os.git`


Execution:
- Run the build for /tests/coap/ in the ArielOS repo root:

`laze -C tests/coap build -b <board>`
- Run ArielOSBOM (where its repo was cloned to) with your project root path and the relative path to the test case's Cargo.toml, because it is not in the root directory, as cli arguments. Since we are in the original ArielOS repository, we do not have an import, so we only have the lock file at the root:

`cargo run -- -r <PATH_TO_MAIN_REPO> -m ./tests/coap/Cargo.toml --import-path ./`

- The output file will be put into the ./output directory.


## To-Do

- complete info for missing SBOM fields (and make it BSI compliant)
    - missing BSI compliance aspects 
    - purl, additional identifiers?

- some niceties:
    - generation for multiple boards at once; generation without needing to access the last build command (aka getting necessary info from laze directly) 
    - make the actual code nicer lol

- redo tests for evaluation metrics

- placeholder

## Future considerations

- component recognition
    - non-Rust components (binary blobs, ...)
    - more accurate Rust component verification
        - accurate check for each compiled component whether it actually affects the final executable or can be omitted as false positive
        - goal: slim down the SBOM; potentially relevant for SBOM storage/processing/transmitting on devices in some distant future

- alternative data gathering in case cargo metadata fails for whatever reason

- extract and include ArielOS/domain specific relevant information
    - device specifications
    - storage/memory footprint
    - supported features/protocols
    - anything else?

## questions/whatever

For feedback of any sorts, I can also be messaged on Matrix: @lekilian:matrix.org