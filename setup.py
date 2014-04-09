#coding=utf-8

from setuptools import setup, find_packages

PACKAGE = 'pyhttpcap'
name = 'pyhttpcap'
description = 'Parse pcap file with python'
author = 'xiaxiaocao'
author_email = 'dongliu@live.cn'
url = 'https://github.com/xiaxiaocao/pyhttpcap'
version = __import__(PACKAGE).__version__

try:
    with open('README.rst') as f:
        long_description = f.read()
except:
    long_description = description

setup(
    name=name,
    version=version,
    description=description,
    long_description=long_description,
    author=author,
    author_email=author_email,
    license='Apache Software License',
    url=url,
    packages=find_packages(exclude=['tests.*', 'tests']),
    include_package_data=True,
    classifiers=[
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Natural Language :: English',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    zip_safe=False,
    scripts=['parse_pcap', 'proxy_cap'],
)