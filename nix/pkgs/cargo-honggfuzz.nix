{
  lib,
  stdenv,
  fetchCrate,
  rustPlatform,
}:
rustPlatform.buildRustPackage rec {
  pname = "honggfuzz";
  # last tagged version is far behind master
  version = "0.5.58";

  src = fetchCrate {
    inherit pname version;
    sha256 = "sha256-3KeRZsuJFGwQQQVdnGCYLIkKjILLgbvCzasInCkYNB0=";
  };

  cargoHash = "sha256-N0MGYcVw3dx7MEtwbehPGaTtIgxBv08nN/u8/cdWQEc=";

  buildInputs = lib.optionals stdenv.isDarwin [ ];
}
