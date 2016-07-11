#!/bin/bash

cd $(dirname $0)
echo "Run test with python2..."
python -m unittest discover tests -p "*_test.py" || exit -1
echo "Run test with python3..."
python3 -m unittest discover tests -p "*_test.py" || exit -1
pandoc -f markdown -t rst -o README.rst README.md
python setup.py register
python setup.py sdist upload
rm -rf httpcap.egg-info/ dist/ build/
