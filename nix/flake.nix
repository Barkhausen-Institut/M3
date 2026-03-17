{
    outputs = { self, nixpkgs }: let

        # flake support
        lib = import "${nixpkgs}/lib";
        forAll = list: f: lib.genAttrs list f;

    in {
        devShells = forAll [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" ] (system: {
            default = import ./shell.nix { inherit nixpkgs system; };
        });
    };
}
