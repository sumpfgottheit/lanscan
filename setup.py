#
# setup.py for lanscan - https://github.com/sumpfgottheit/lanscan
#
from setuptools import setup
import os

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='lanscan',
    version='0.0.4',

    description='Python 3 module to collect and display information about the hosts and devices on the local network',
    long_description=read("README.rst"),
    keywords='network scanner active passive dpkt html',

    # The project's main homepage.
    url='https://github.com/sumpfgottheit/lanscan',

    # Author details
    author='Florian Sachs',
    author_email='florian.sachs@gmx.at',

    # Choose your license
    license='MIT',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        #'Intended Audience :: Developers',
        #'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.5',

        # Operating systems this runs on
        'Operating System :: Unix',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',

        # what does this do?
        'Topic :: Utilities',
#        'Topic :: System :: Shells',
#        'Environment :: Console'
    ],

    packages=['lanscan'],
    install_requires=['requests','netaddr', 'click'],
    entry_points={
        'console_scripts': [
            'lanscan=lanscan.lanscan:main',
        ],
    },
)
