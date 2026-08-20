**Like the README comparison, this document requires an update that will happen with the eventual rewrite.**

This file provides additional details to the [README's comparison](https://github.com/Nerving/ArielOSBOM?tab=readme-ov-file#comparison).

## Setup

The project used is the [v0.4.0 Ariel OS CoAP test](https://github.com/ariel-os/ariel-os/tree/v0.4.0/tests/coap), but recreated as an out-of-tree project, and built for the nRF52840-DK board. It was set up as follows:

1. [set up a new project from a template repository](https://ariel-os.github.io/ariel-os/dev/docs/book/getting-started.html#starting-an-application-project-from-a-template-repository)

2. copy `main.rs`/its code from the [Ariel OS CoAP test](https://github.com/ariel-os/ariel-os/tree/v0.4.0/tests/coap/src/main.rs) to the test repository

3. edit `Cargo.toml`

    - add the missing dependencies from the original [test's](https://github.com/ariel-os/ariel-os/blob/v0.4.0/tests/coap/Cargo.toml) `Cargo.toml` to the new `Cargo.toml` (everything besides `ariel-os` and `ariel-os-boards`)

    - for the dependencies taking the information declared in the original Ariel OS workspace (`<DEPENDENCY> = { workspace = true }`), copy the information from the [Ariel OS main](https://github.com/ariel-os/ariel-os/blob/v0.4.0/Cargo.toml) `Cargo.toml`

    - add the `[patch.crates-io]` section from the [main repo's](https://github.com/ariel-os/ariel-os/blob/v0.4.0/ariel-os-cargo.toml) `ariel-os-cargo.toml` to the new `Cargo.toml` (necessary?)

4. edit `laze-project.yml`

    - add the three selects from the original [test's](https://github.com/ariel-os/ariel-os/blob/v0.4.0/tests/coap/laze.yml) `laze.yml` to the new `laze-project.yml`

    - (make sure that the git import tag is v0.4.0)

## Tools

- cargo tree (baseline)
    - displays the dependency graph of a project
    - can take features, and environment variables also affect the dependency resolution
    - thus provides accurate dependency resolution for a specific build if the respective build-parameters are provided
        - includes only crates that were actually compiled and are thus relevant to the specific build

- ArielOSBOM
    - cargo tree based, so basically baseline as well
    - then filters recognised crates from `cargo metadata` output
    - takes existing or generates laze build command and parses features and environment variables from it

- [Syft](https://github.com/anchore/syft) 1.42.3
    - general purpose generator
    - no options to provide features etc.
    - obtains Rust info from `Cargo.lock`

- [cdxgen](https://github.com/cdxgen/cdxgen) 12.1.4
    - general purpose generator
    - no options to provide features etc.
    - obtains Rust info from `Cargo.lock`

- [cargo-sbom](https://github.com/psastras/sbom-rs) 0.10.0
    - Rust native
    - no option to provide features, environment variables during call have no effect
    - obtains information from `cargo metadata`

- [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo) 0.5.9
    - Rust native
    - supports --features, environment variables affect result
    - obtains information from `cargo metadata`, `Cargo.lock`

## Metrics and Results

The different tools will be measured compared to the baseline according to how many false positives [FP] (components recognised by the tool but not the baseline) and false negatives [FN] (components recognised by the baseline but not the tool) they yield. The total number of components they provide will also be displayed. For the evaluation, only component name and component version are considered.

The commands used to generate the SBOMs (or the cargo tree baseline) are listed below. [1]

- cargo tree (baseline)
    - 312 unique components

- ArielOSBOM
    - 312 unique components
    - 0 FP, 0 FN
    - this tool uses cargo tree itself, so it matches with the baseline

- Syft
    - no import exclusion
        - 1205 total components, 878 unique ones; duplicates because of root and import `Cargo.lock` file analysis
        - 568 FPs
        - 2 FNs: semihosting 0.1.25, getrandom 0.3.4
    - import exclusion
        - 508 total components
        - 211 FPs
        - 15 FNs [1]
    - inclusion of import lock file catches (almost all) dependencies that for some reason to not end up in root lock file, but also all other dependencies irrelevant to the current build
    - includes the `Cargo.lock` file(s) as components

- cdxgen
    - 507 total components
    - 210 FPs, 15 FNs
    - same as Syft; one less total and FP because no `Cargo.lock` file(s) listed

- cargo-sbom
    - 392 total components
    - 151 FPs
    - 71 FNs [2]
    - should be similar to Syft/cdxgen, but obviously is not

- cargo-cyclonedx
    - 380 total components
    - 71 FPs
    - 3 FNs: iana-time-zone 0.1.65, linux-raw-sys 0.12.1, rustix 1.1.4
    



---


[1] list of generation commands:
- cargo tree (envs and features copied from `/build/build-local.ninja)
```
OPENOCD_ARGS="-f board/nordic_nrf52_dk.cfg" SCRIPTS=./scripts CONFIG_BOARD=nrf52840dk CARGO_BUILD_TARGET=thumbv7em-none-eabihf CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUNNER='probe-rs run --protocol=swd --chip nrf52840_xxAA --preverify' CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS="--cfg context=\"nrf52840dk\" --cfg context=\"nrf52840\" --cfg context=\"nrf52\" --cfg context=\"nrf\" --cfg context=\"ariel-os\" --cfg context=\"default\" --cfg getrandom_backend=\"custom\" --cfg stable -Cembed-bitcode=yes -Clto=fat -Ccodegen-units=1 --cfg capability=\"hw/device-identity\" -Clink-arg=-Tdefmt.x --cfg armv7m --cfg armv7m_eabihf -Clink-arg=${LINK_ARG_PREFIX}--nmagic -Clink-arg=${LINK_ARG_PREFIX}--no-eh-frame-hdr -Clink-arg=-Tlinkme.x -Clink-arg=-Tlink.x -Clink-arg=-Teheap.x -Clink-arg=-Tdevice.x -Clink-arg=-Tisr_stack.x --cfg context=\"cortex-m\" --cfg context=\"cortex-m4f\" --cfg capability=\"hw/usb-device-port\"" CARGO_TARGET_DIR=./build/bin/nrf52840dk/cargo CONFIG_EXECUTOR_STACKSIZE=32768 CONFIG_ISR_STACKSIZE=2048 CC="${CC}" CFLAGS="${CFLAGS}" DEFMT_LOG=info,${LOG} ${CARGO_WRAPPER} cargo tree --prefix none --features=ariel-os/coap-server-config-demokeys,ariel-os/liboscore-provide-abort,ariel-os/liboscore-provide-assert,ariel-os/hwrng,ariel-os/random,ariel-os/semihosting,ariel-os/single-core,ariel-os/executor-interrupt,ariel-os/defmt-rtt,ariel-os/panic-printing,ariel-os/defmt,ariel-os/debug-console,ariel-os/usb,ariel-os/usb-ethernet,ariel-os/dhcpv4,ariel-os/ipv4,ariel-os/coap-transport-udp,ariel-os/coap,ariel-os/coap-server
```

- ArielOSBOM (in its own repository)
```
cargo run -- -r <PATH_TO_PROJECT_ROOT> -b cdx_1.6 --builders nrf52840dk
```

- Syft
```
<PATH_TO_SYFT>/syft scan ./ (--exclude "./build/imports/**") (--override-default-catalogers rust) -o cyclonedx-json=<OUTPUT_NAME>
```

including `--override-default-catalogers` or not made no difference to the results

- cdxgen
```
<PATH_TO_CDXGEN>/cdxgen -t rust --exclude "./build/imports/**"
```

not excluding the imports directory would provide a result similar to Syft's without the exclude, as they operate the same way

- cargo-sbom
```
cargo sbom --output-format cyclone_dx_json_1_6 ./
```

- cargo-cyclonedx
```
OPENOCD_ARGS="-f board/nordic_nrf52_dk.cfg" SCRIPTS=./scripts CONFIG_BOARD=nrf52840dk CARGO_BUILD_TARGET=thumbv7em-none-eabihf CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUNNER='probe-rs run --protocol=swd --chip nrf52840_xxAA --preverify' CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS="--cfg context=\"nrf52840dk\" --cfg context=\"nrf52840\" --cfg context=\"nrf52\" --cfg context=\"nrf\" --cfg context=\"ariel-os\" --cfg context=\"default\" --cfg getrandom_backend=\"custom\" --cfg stable -Cembed-bitcode=yes -Clto=fat -Ccodegen-units=1 --cfg capability=\"hw/device-identity\" -Clink-arg=-Tdefmt.x --cfg armv7m --cfg armv7m_eabihf -Clink-arg=${LINK_ARG_PREFIX}--nmagic -Clink-arg=${LINK_ARG_PREFIX}--no-eh-frame-hdr -Clink-arg=-Tlinkme.x -Clink-arg=-Tlink.x -Clink-arg=-Teheap.x -Clink-arg=-Tdevice.x -Clink-arg=-Tisr_stack.x --cfg context=\"cortex-m\" --cfg context=\"cortex-m4f\" --cfg capability=\"hw/usb-device-port\"" CARGO_TARGET_DIR=./build/bin/nrf52840dk/cargo CONFIG_EXECUTOR_STACKSIZE=32768 CONFIG_ISR_STACKSIZE=2048 CC="${CC}" CFLAGS="${CFLAGS}" DEFMT_LOG=info,${LOG} ${CARGO_WRAPPER} cargo cyclonedx -f json --features=ariel-os/coap-server-config-demokeys,ariel-os/liboscore-provide-abort,ariel-os/liboscore-provide-assert,ariel-os/hwrng,ariel-os/random,ariel-os/semihosting,ariel-os/single-core,ariel-os/executor-interrupt,ariel-os/defmt-rtt,ariel-os/panic-printing,ariel-os/defmt,ariel-os/debug-console,ariel-os/usb,ariel-os/usb-ethernet,ariel-os/dhcpv4,ariel-os/ipv4,ariel-os/coap-transport-udp,ariel-os/coap,ariel-os/coap-server --spec-version 1.5
```

---

[2] Syft, import exclusion; list of FNs
- defmt-parser v1.0.0
- defmt v0.3.100
- defmt v1.0.1
- defmt-macros v1.0.1
- semihosting v0.1.25
- embassy-net v0.8.0
- getrandom v0.3.4
- rand_pcg v0.9.0
- ariel-os-random v0.4.0
- defmt-rtt v1.1.0
- managed v0.8.0
- rand_chacha v0.9.0
- embedded-nal-async v0.9.0
- ppv-lite86 v0.2.21
- smoltcp v0.12.0

---

[3] cargo-sbom; list of FNs
- peg-runtime v0.8.5
- eyre v0.6.12
- semihosting v0.1.25
- cc v1.2.59
- defmt v1.0.1
- peg-macros v0.8.5
- anstyle-query v1.1.5
- hexfloat2 v0.1.3
- walkdir v2.5.0
- ariel-os-random v0.4.0
- itertools v0.13.0
- either v1.15.0
- coap-4-0 v0.1.0
- encoding_rs v0.8.35
- bindgen v0.72.1
- managed v0.8.0
- peg v0.8.5
- rustc_version v0.2.3
- defmt v0.3.100
- getrandom v0.4.2
- anstyle-parse v1.0.0
- clap_lex v1.1.0
- defmt-rtt v1.1.0
- utf8parse v0.2.2
- cbindgen v0.29.2
- embedded-nal-async v0.9.0
- winnow v0.7.15
- defmt-macros v1.0.1
- toml v0.9.12+spec-1.1.0
- smoltcp v0.12.0
- indenter v0.3.4
- prettyplease v0.2.37
- autocfg v1.5.0
- version_check v0.9.5
- ld-memory v0.2.9
- same-file v1.0.6
- libloading v0.8.9
- zmij v1.0.21
- clap_derive v4.6.0
- getrandom v0.3.4
- rustc-hash v2.1.2
- defmt-parser v1.0.0
- clap_builder v4.6.0
- build-rs v0.3.3
- colorchoice v1.0.5
- glob v0.3.3
- find-msvc-tools v0.1.9
- anstyle v1.0.14
- semver v0.9.0
- serde_json v1.0.149
- toml_datetime v0.7.5+spec-1.1.0
- anstream v1.0.0
- ppv-lite86 v0.2.21
- tempfile v3.27.0
- cbor-edn v0.0.9
- shlex v1.3.0
- data-encoding-macro-internal v0.1.17
- clap v4.6.0
- data-encoding-macro v0.1.19
- rustix v1.1.4
- is_terminal_polyfill v1.70.2
- rand_pcg v0.9.0
- semver-parser v0.7.0
- cexpr v0.6.0
- rand_chacha v0.9.0
- is-terminal v0.4.17
- clio v0.3.5
- clang-sys v1.8.1
- fastrand v2.3.0
- embassy-net v0.8.0
- linux-raw-sys v0.12.1