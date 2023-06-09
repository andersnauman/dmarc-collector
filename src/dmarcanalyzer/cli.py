#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC analyzer """

import argparse
import logging

from dmarcparser import dmarc_from_folder

logging.basicConfig(filename="analyzer.log", level=logging.INFO)

def _run():
    """ Main """

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("-f", "--folder", help="import from folder")
    # pylint: disable-next=line-too-long
    parser.add_argument("-r", "--recursive", help="search for files recursively", action="store_true")
    args = parser.parse_args()
    run_args = {}
    if args.verbose:
        run_args["log_level"] = logging.DEBUG
    if args.folder:
        run_args["folder"] = args.folder
    run_args["recursive"] = args.recursively

    print(f"## Testing folder: {run_args['folder']}")
    dmarc_from_folder(**run_args)

if __name__ == "__main__":
    _run()
