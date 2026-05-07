# Examples

This directory contains two examples intended for taking a first look at this tool and the SBOMs it produces. All paths listed here are relative to the project root.

## ariel_os_example

This example uses the Ariel OS fixture present in `tests/fixtures/ariel-os` and generates an example CycloneDx 1.6 SBOM of the `coap-client` example using the `nrf52840dk` builder.

### How to run

At this project's root, run

    cargo run --example ariel_os_example

The generated SBOM will be written into `output/ariel-os-example_nrf52840dk.1-6.cdx.json`.


<br><br>


## custom_oot_project

This example generates a CycloneDx 1.6 SBOM for your [out-of-tree project](https://ariel-os.github.io/ariel-os/dev/docs/book/getting-started.html#starting-an-application-project-from-a-template-repository) of choice using the `nrf52840dk` builder by default or, if provided, another specified builder.

### How to run

At this project's root, run

    cargo run --example custom_oot_project -- -r <PATH_TO_PROJECT> [-b <BUILDER>]

where

- (-r, required) path to the project root for which the SBOM is to be generated for; if you do not have any own project to try this out on, you can use the fixture at `tests/fixtures/out-of-tree-coap-client`

- (-b, optional) alternative [builder](https://ariel-os.github.io/ariel-os/dev/docs/book/hardware-functionality-support.html) in case the specified project requires a builder that is not `nrf52840dk`



The generated SBOM will be written into `output/custom-oot-example_nrf52840dk.1-6.cdx.json`.