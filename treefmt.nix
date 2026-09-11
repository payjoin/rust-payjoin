{ pkgs, ... }:
{
  projectRootFile = "flake.nix";
  programs = {
    dart-format.enable = true;
    clang-format.enable = true;
    nixfmt.enable = true;
    prettier.enable = true;
    ruff-format.enable = true;
    rustfmt = {
      enable = true;
      package = pkgs.rustToolchains.nightly;
      edition = "2021";
    };
    shellcheck = {
      enable = true;
      external-sources = true;
    };
    shfmt = {
      enable = true;
      indent_size = 4;
    };
    taplo.enable = true;
  };
  settings = {
    formatter = {
      clang-format.includes = [ "payjoin-ffi/cpp/tests/*" ];
      dart-format.options = [
        "--language-version"
        "latest"
      ]; # https://github.com/dart-lang/sdk/issues/60163#issuecomment-2668274823
      rustfmt.options = [
        "--config-path"
        "./rustfmt.toml"
      ];
      shellcheck.includes = [ "*.sh" ];
      shellcheck.excludes = [ "*.envrc" ];
      shfmt = {
        includes = [ "*.sh" ];
        excludes = [ "*.envrc" ];
        options = [
          "--case-indent"
        ];
      };
    };
  };
}
