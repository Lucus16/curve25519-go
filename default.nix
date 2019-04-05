{ pkgs ? import <nixpkgs> {} }:

with pkgs;

buildGoPackage {
  name = "curve25519-go";
  src = ./.;
  goPackagePath = "github.com/Lucus16/curve25519-go";
}
