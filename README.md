# payjoin-ffi

# Bindings for PDK

This repository creates the `libpdkffi` multi-language library for the Rust-based [PDK](https://payjoindevkit.org/) from the [Payjoin Dev Kit] project.

Each supported language and the platform(s) it's packaged for has its own directory. The Rust code in this project is in the bdk-ffi directory and is a wrapper around the [bdk] library to expose its APIs in a uniform way using the [mozilla/uniffi-rs] bindings generator for each supported target language.
