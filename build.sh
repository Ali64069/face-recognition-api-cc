#!/usr/bin/env bash

set -e
set -u
set -x

export DEST=source/.webpack
export PUBLIC_URL="./"

npm install -g yarn

cd source
rm -rf package-lock.json
yarn install
yarn build
cd -