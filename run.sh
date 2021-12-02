#!/bin/bash

set -euo pipefail

pushd probes
    echo Building elf..
    cargo bpf build --target-dir=../target
popd

pushd cmd/ebpf
    echo Running Go program...
    go run -exec sudo main.go
popd
