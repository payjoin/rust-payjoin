fn main() {
    uniffi::generate_scaffolding("src/payjoin_ffi.udl").unwrap();
    #[cfg(feature = "dart")]
    uniffi_dart::generate_scaffolding("src/payjoin_ffi.udl".into()).unwrap();
}
