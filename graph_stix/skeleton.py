#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a skeleton file that can serve as a starting point for a Python
console script. To run this script uncomment the following line in the
entry_points section in setup.cfg:

    console_scripts =
     fibonacci = graph_stix.skeleton:run

Then run `python setup.py install` which will install the command `fibonacci`
inside your current environment.
Besides console scripts, the header (i.e. until _logger...) of this file can
also be used as template for Python modules.

Note: This skeleton file can be safely removed if not needed!
"""
from __future__ import division, print_function, absolute_import
from graph_stix import __version__
from graph_stix.graph_sticks import parse_data
from stix.core import STIXPackage
from stix.utils.parser import UnsupportedVersionError

import argparse
import os,sys

# logging
import logging

__author__ = "arangaraju"
__copyright__ = "arangaraju"
__license__ = "none"

_logger = logging.getLogger(__name__)

def test_GreenIOC():
    test_path = '../Green_IOCs/'
    test_data = os.listdir(test_path)

    _logger.info('Opening all files in Green_IOCs')

    for fle in test_data:
        try:
            myfile = str(test_path) + str(fle)
            if myfile:
                parse_file(myfile)
        except UnsupportedVersionError, err:
            _logger.info("-> Skipping %s\n    UnsupportedVersionError: %s" % (myfile, err))
            _logger.info("See https://github.com/STIXProject/python-stix/issues/124")
        except Exception, err:
            _logger.info("-> Unexpected error parsing %s: %s; skipping." % (myfile, err))
    _logger.info('Closing all files in Green_IOCs')


def test_files():
    # PATH vars
    #here = lambda *x: join(abspath(dirname(__file__)), *x)
    #PROJECT_ROOT = here("..")
    #root = lambda *x: join(abspath(PROJECT_ROOT), *x)
    #sys.path.insert(0, root('TEST'))
    test_path = '../TEST/'
    test_data = os.listdir(test_path)

    _logger.info('Opening files in TEST')

    for fle in test_data:
        if not fle.endswith("xml"):
            continue
        myfile = str(test_path) + str(fle)
        if myfile:
            parse_file(myfile)

    _logger.info('Closing files in TEST')

def parse_args(args):
    """
    Parse command line parameters

    :param args: command line parameters as list of strings
    :return: command line parameters as :obj:`argparse.Namespace`
    """
    parser = argparse.ArgumentParser(
        description="STIX Graph Database : Demonstration"
        '--version',
        action='version',
        version='graph-stix {ver}'.format(ver=__version__))

    parser.add_argument(
        '-v',
        '--verbose',
        dest="loglevel",
        help="set loglevel to INFO",
        action='store_const',
        const=logging.INFO)
    parser.add_argument(
        '-vv',
        '--very-verbose',
        dest="loglevel",
        help="set loglevel to DEBUG",
        action='store_const',
        const=logging.DEBUG)
    return parser.parse_args(args)

def parse_file(myfile):
    f = open(myfile)
    #Parse the input file
    _logger.info('Parsing input file '+str(f))

    try:
        stix_package = STIXPackage.from_xml(f)
        parse_data(stix_package)

    except ValueError:
        _logger.info('Input file %s cannot be parsed', str(f))
        f.close()
        return

    #Close file
    f.close()


def test_file(myfile):
    _logger.info('Opening test file to parse')
    parse_file(myfile)


def main(args):
    if args:
        args = parse_args(args)
        logging.basicConfig(level=args.loglevel, stream=sys.stdout)
    else:
        logging.basicConfig(level=logging.INFO, format=u'[%(asctime)s]  %(message)s')

    _logger.debug("Allons-y...!!")

    test_file('../TEST/Tryout.xml')
    test_file('../TEST/11.xml')
    #test_files()
    #test_GreenIOC()

    _logger.info("Aloha !")


def run():
    reload(logging)
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
