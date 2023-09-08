fn main() {
	uniffi::generate_scaffolding("bindings/pdk_ffi.udl").unwrap();
}
