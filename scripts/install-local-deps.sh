#!/bin/bash

set -e

mkdir dep-tmp
git clone https://github.com/oxen-io/oxen-pyoxenc ./dep-tmp/oxenc
git clone https://github.com/oxen-io/oxen-pyoxenmq ./dep-tmp/oxenmq
pip install ./dep-tmp/oxenc ./dep-tmp/oxenmq

rm -rf dep-tmp

pip install -r requirements.txt
