#!/bin/bash

set -ex

cd ykman-rs
cargo +nightly test
cargo +nightly build

cd ..
python setup.py test
