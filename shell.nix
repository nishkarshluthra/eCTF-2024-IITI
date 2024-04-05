/**
 * @file "shell.nix"
 * @author Ben Janis
 * @brief Nix shell environment file
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

{ pkgs ? import <nixpkgs> {}
  , fetchzip ? pkgs.fetchzip
  , fetchgit ? pkgs.fetchgit
  , fetchurl ? pkgs.fetchurl
  , unzip ? pkgs.unzip
}:

pkgs.mkShell {
  buildInputs = [
    pkgs.gnumake
    pkgs.python39
    pkgs.gcc-arm-embedded
    pkgs.poetry
    pkgs.cacert
    (pkgs.callPackage custom_nix_pkgs/analog_openocd.nix { })
    pkgs.minicom
  ];

  msdk = builtins.fetchGit {
    url = "https://github.com/Analog-Devices-MSDK/msdk.git";
    ref = "refs/tags/v2023_06";
  };

   wolfssl = builtins.fetchGit {
    url = "https://github.com/wolfSSL/wolfssl.git";
    ref = "refs/tags/v5.6.3-stable";
  };


  shellHook =
    ''
      cp -r $msdk $PWD/msdk
      chmod -R u+rwX,go+rX,go-w $PWD/msdk
      export MAXIM_PATH=$PWD/msdk
      cp -r $wolfssl $PWD/wolfssl
      chmod -R u+rwX,go+rX,go-w $PWD/wolfssl
      sed -i 's/-std=c++11/-std=c++14/g' $PWD/msdk/Libraries/CMSIS/Device/Maxim/GCC/gcc.mk
      poetry install
    '';
}
