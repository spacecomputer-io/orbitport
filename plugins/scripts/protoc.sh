#!/bin/bash

# if there is no /go/bin in the PATH, add it
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    export PATH="$HOME/go/bin:$PATH"
fi
(protoc-gen-go --version &> /dev/null) || (echo "Missing protoc-gen-go" && exit 1)
(protoc-gen-go-grpc --version &> /dev/null) || (echo "Missing protoc-gen-go-grpc" && exit 1)

if [[ "$PWD" != *"/plugins" ]]; then
    cd plugins
fi

mkdir -p proto && mkdir -p .backup/proto && cp -r ./proto/ .backup/proto
cp -r ../proto/plugins ./proto

protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative ./proto/**/*.proto

# remove all the proto files from the proto directory, since we only want the generated .pb.go files
find ./proto -type f -name "*.proto" -delete

## if passed --dry-run flag, just print the diff for the relevant files
if [ "$1" == "--dry-run" ]; then
    git diff --exit-code --name-only | grep '\.pb\.go$'
    cp -r .backup/proto .
fi