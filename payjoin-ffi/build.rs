fn main() {
    uniffi::generate_scaffolding("src/payjoin.udl").unwrap();
    #[cfg(feature = "dart")]
    uniffi_dart::generate_scaffolding("src/payjoin.udl".into()).unwrap();
}
