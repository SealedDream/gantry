#!/bin/sh
# Builds the plugin helper (plugin-host/, PLUG-02b) for the Mac bundle and copies it to
# Generated/plugin-host/bastion-plugin-host, where bundle.sh takes it from.
set -eu
cd "$(dirname "$0")"
( cd ../../plugin-host && nice -n 10 cargo build --release -j 4 )
mkdir -p Generated/plugin-host
cp ../../plugin-host/target/release/bastion-plugin-host Generated/plugin-host/bastion-plugin-host
chmod 755 Generated/plugin-host/bastion-plugin-host
