fn main() {
    #[cfg(feature = "uniffi")]
    uniffi::uniffi_bindgen_main();
    #[cfg(feature = "uniffi")]
    uniffi_dart::gen::generate_dart_bindings(
        "src/payjoin_ffi.udl".into(),
        None,
        Some("dart/lib".into()),
        "target/release/libpayjoin_ffi.dylib".into(),
        true,
    )
    .unwrap();
}
