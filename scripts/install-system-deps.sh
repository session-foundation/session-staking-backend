#!/bin/bash

set -e

sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
sudo apt update
sudo apt install build-essential python3-pip python3-dev pybind11-dev liboxenc-dev liboxenmq-dev python3.12-venv
