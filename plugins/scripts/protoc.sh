#!/bin/bash

export PATH="$HOME/go/bin:$PATH"



(protoc-gen-go --version &> /dev/null) || (echo "Missing protoc-gen-go" && exit 1)

## create .backup folder just in case
mkdir -p .backup/proto && cp -r ./proto/* .backup/proto

protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative ./**/*.proto

## if passed --dry-run flag, just print the diff for the relevant files
if [ "$1" == "--dry-run" ]; then
    git diff --exit-code --name-only | grep '\.pb\.go$'
    cp -r .backup/proto/* ./proto
fi