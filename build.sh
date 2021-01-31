#!/usr/bin/bash

os=linux
for arch in "amd64" "386" "mips64" "mips64le" "arm" "arm64";do
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -o build/nothing_linux_$arch
done

os=darwin
for arch in "amd64";do
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -o build/nothing_darwin_$arch
done

os=windows
for arch in "amd64" "386" "arm";do
    GOEXE=.exe CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -o build/nothing_windows_$arch
done