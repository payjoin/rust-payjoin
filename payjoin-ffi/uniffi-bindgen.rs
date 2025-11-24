fn main() { uniffi_bindgen() }

fn uniffi_bindgen() {
    // uniffi_bindgen_main parses command line arguments for officially supported languages,
    // but we need to parse them manually first to decide whether to use the uniffi_dart plugin.
    let args: Vec<String> = std::env::args().collect();
    let language =
        args.iter().position(|arg| arg == "--language").and_then(|idx| args.get(idx + 1));
    match language {
        #[cfg(feature = "dart")]
        Some(lang) if lang == "dart" => {
            let library_path = args
                .iter()
                .position(|arg| arg == "--library")
                .and_then(|idx| args.get(idx + 1))
                .expect("specify the library path with --library");
            let output_dir = args
                .iter()
                .position(|arg| arg == "--out-dir")
                .and_then(|idx| args.get(idx + 1))
                .expect("--out-dir is required when using --library");
            uniffi_dart::gen::generate_dart_bindings(
                "src/payjoin.udl".into(),
                Some("uniffi.toml".into()),
                Some(output_dir.as_str().into()),
                library_path.as_str().into(),
                true,
            )
            .expect("Failed to generate dart bindings");
        }
        _ => uniffi::uniffi_bindgen_main(),
    }
}
