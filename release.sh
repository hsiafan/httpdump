#!/bin/bash

cd $(dirname $0)
pandoc -f markdown -t rst -o README.rst README.md
python setup.py register
python setup.py sdist upload
rm -rf httpcap.egg-info/ dist/
