import codecs

from setuptools import setup


with codecs.open('README.rst', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pcap-parser',
    version='0.5.8',
    description='Parse pcap file with python',
    long_description=long_description,
    author='xiaxiaocao',
    author_email='im@dongliu.net',
    license='Apache Software License',
    url='https://github.com/xiaxiaocao/pcap-parser',
    packages=['pcapparser'],
    install_requires=[],
    include_package_data=True,
    classifiers=[
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD 2-Clause License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    zip_safe=False,
    # scripts=['parse_pcap'],
    entry_points={
        'console_scripts': [
            'parse_pcap = pcapparser.__main__:main',
        ],
    }
)