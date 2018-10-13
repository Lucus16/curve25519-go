{ pkgs ? import <nixpkgs> {} }:

with pkgs;

buildGoPackage {
  name = "curve25519-go";
  goPackagePath = /var/empty;
}
