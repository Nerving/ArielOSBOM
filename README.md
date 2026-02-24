This repository is for the WIP project for my bachelor's thesis (Comp. Sci., FU Berlin) under the guidance of [Prof. Dr. Emmanuel Baccelli](https://emmanuelbaccelli.com/). 

## Motivation and Goals

With increasing software supply chain attacks and security demands, Software Bills of Materials (SBOMs) have gained relevance in recent years. In the EU, the [Cyber Resilience Act (CRA)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) will be requiring suppliers to draw up and if necessary provide SBOMs for their software. As a FOSS project, ArielOS itself technically does not fall under the CRA, however as seen with [RIOT e.g.](https://github.com/RIOT-OS/RIOT/pull/21530) demand can exist for users of ArielOS, so providing tooling to support with that makes sense. 

The goal of this project is to create/lay the groundwork for an SBOM generator for [Ariel OS](https://github.com/ariel-os/ariel-os) projects. Since the CRA does not go into much detail in terms of SBOM requirements, right now the current [BSI technical guideline for SBOMs](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf) will instead be used as a reference and compliance for it be strived towards.

## Current state

Kind of a first skeleton. Like other tools it only addresses Cargo related components so far. By using [cargo-bloat](https://crates.io/crates/cargo-bloat) to determine what actually lands in the final code, the amount of false positives can be reduced.

As of now the tool does the following:
- extract build information from the last laze build command
- generate cargo-tree data for component baseline
- run cargo metadata for info crate metadata
- filter only the crates listed by cargo tree
- take available relevant information from (filtered) cargo metadata
- write output to file, no SPDX/Cyclone-DX so far

## Usage

### Installation

- install the [build prerequisites] needed to build ArielOS projects
- if not done already, install nightly toolchain: `rustup toolchain install nightly`

### Execution

- run the build process for which you want to generate the SBOM first (program takes latest command from ./builds/build-local.ninja) 
- only works using nightly toolchain right now (otherwise cargo metadata fails for ArielOS projects)
- provide the project's root path via the command line (`-r <PATH>`)

Current cli arguments:
```
    -r, --root-path     <PATH>              Path to project root [default: ./] REQUIRED
    -b, --bom-formats   <BOM_FORMAT>        BOM formats to generate [default: Raw] (only Raw so far, later SPDX and/or Cyclone-DX)
    -f, --file-format   <FILE_EXTENSION>    Data format of the generated SBOM [default: json] (only .json so far)
    -o, --output-name   <FILE_NAME>         File name of the generated SBOM [default: arielosbom]

    -m, --manifest-path <PATH>              Path to the build's manifest file relative to its root [default: ./Cargo.toml]
    -l, --lock-path     <PATH>              Path to the project's lock file relative to its root [default: ./Cargo.lock]   
    -i  --import-path   <PATH>              Path to the project's ArielOS import directory relative to its root [default: ./build/imports/ariel-os]
```

### Example (ArielOS Coap Test)

Installation + Setup:
- Clone the repo to a location of your choosing: 

`git clone https://github.com/Nerving/ArielOSBOM.git`

- Install nightly toolchain and set it as default:

`rustup toolchain install nightly`, `rustup default nightly`

- Clone the ArielOS main repo:

`git clone https://github.com/ariel-os/ariel-os.git`


Execution:
- Run the build for /tests/coap in the ArielOS repo root:

`laze -C tests/coap build -b <board>`
- Note: This is not accurate as of now and will have to be fixed. Run ArielOSBOM (where its repo was cloned to) with your project root path and the relative path to the test case's Cargo.toml because it is not in the root directory as cli arguments. Since we are in the original ArielOS repository, we do not have an import, so we only have the lock file at the root:

`cargo run -- -r <PATH> -m ./tests/coap/Cargo.toml --import-path ./`

- The output file will be put into the ArielOSBOM root directory.

### Alternative example for out-of-tree ArielOS projects

Installation + Setup:
- as before except:

- ~~Clone the ArielOS main repo:~~ Have your own project [set up from a template repository](https://ariel-os.github.io/ariel-os/dev/docs/book/getting-started.html#starting-an-application-project-from-a-template-repository)


Execution:
- Run the build for your project:

`laze build -b <board>`

- Run ArielOSBOM (where its repo was cloned to) with your project root path as cli argument.

`cargo run -- -r <PATH>`

- The output file will be put into the ArielOSBOM root directory.

## To-Do

- fix test/example case usage
- complete info for missing SBOM fields (and make it BSI compliant)
    - metadata: additional SPDX/Cyclone-DX specific information
    - provide output directly into at least one of SPDX/Cyclone-DX
    - determine which additional component identifiers (besides component hash) to use

- some niceties:
    - generate for multiple devices, multiple BOM/file formats at once
    - make the actual code nicer lol

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