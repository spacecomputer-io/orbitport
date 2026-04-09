#!/bin/bash

export PATH="$HOME/go/bin:$PATH"
(protoc-gen-go --version &> /dev/null) || (echo "Missing protoc-gen-go" && exit 1)
(protoc-gen-go-grpc --version &> /dev/null) || (echo "Missing protoc-gen-go-grpc" && exit 1)

TARGET_DIR=./plugins

mkdir -p $TARGET_DIR/proto
cp -r $TARGET_DIR/proto $TARGET_DIR/.backup/proto

echo "Generating Go code from proto files..."
protoc --go_out=$TARGET_DIR --go_opt=paths=source_relative \
    --go-grpc_out=$TARGET_DIR --go-grpc_opt=paths=source_relative ./proto/plugins/*.proto

if [ "$1" == "--dry-run" ]; then
    git diff --exit-code --name-only | grep '\.pb\.go$'
    cp -r $TARGET_DIR/.backup/proto $TARGET_DIR/proto
fi
