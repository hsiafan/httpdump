import codecs

from setuptools import setup

with codecs.open('README.rst', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='httpcap',
    version='0.7.7',
    description='Capture and parse http traffics with python',
    long_description=long_description,
    author='xiaxiaocao',
    author_email='dongliu@live.cn',
    license='Simplified BSD License',
    url='https://github.com/caoqianli/httpcap',
    packages=['httpcap', 'pcappy_port'],
    install_requires=[
        "six"
    ],
    include_package_data=True,
    test_suite="tests",
    classifiers=[
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    zip_safe=True,
    entry_points={
        'console_scripts': [
            'parse-pcap = httpcap.__main__:parse_pcap',
            'parse-live = httpcap.__main__:parse_live',
        ],
    }
)
