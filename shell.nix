{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell { nativeBuildInputs = with pkgs; [ cacert clojure gnumake git ]; }
