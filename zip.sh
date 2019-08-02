#!/usr/bin/env bash

./build.sh
export DEST=source/.webpack

cd ${DEST}
zip -r archive.zip .
open .
