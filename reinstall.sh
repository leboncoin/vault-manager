#!/bin/sh

pip uninstall -y vaultmanager
rm -f dist/*
python setup.py sdist
pip install dist/*
