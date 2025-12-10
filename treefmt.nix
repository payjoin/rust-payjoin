{ pkgs, ... }:
{
  projectRootFile = "flake.nix";
  programs = {
    dart-format.enable = true;
    nixfmt.enable = true;
    prettier.enable = true;
    ruff-format.enable = true;
    rustfmt = {
      enable = true;
      package = pkgs.rustToolchains.nightly;
      edition = "2018";
    };
    shellcheck.enable = true;
    shfmt = {
      enable = true;
      indent_size = 4;
    };
    taplo.enable = true;
  };
  settings = {
    formatter = {
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
