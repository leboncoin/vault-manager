#!/bin/sh

pip uninstall -y vaultmanager
python setup.py sdist
pip install dist/vaultmanager-0.0.0.tar.gz
