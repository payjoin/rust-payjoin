fn main() {
    #[cfg(feature = "uniffi")]
    uniffi::generate_scaffolding("src/payjoin_ffi.udl").unwrap();
    #[cfg(feature = "uniffi")]
    uniffi_dart::generate_scaffolding("src/payjoin_ffi.udl".into()).unwrap();
}
