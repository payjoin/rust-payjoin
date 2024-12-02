fn main() {
    #[cfg(feature = "uniffi")]
    uniffi::generate_scaffolding("src/payjoin_ffi.udl").unwrap();
}
