#!/usr/bin/env bash

root=$(pwd)
target=$1

lcldir="${root}/app/local"
srvdir="${root}/app/server"

echo "start build ${target} app..."
case "${target}" in
  "local")
    cd "${lcldir}" || exit
    go build -o "${root}/hk-local" .
    ;;
  "server")
    cd "${srvdir}" || exit
    go build -o "${root}/hk-server" .
    ;;
  "*")
    echo "invalid build target, only support local and server"
esac