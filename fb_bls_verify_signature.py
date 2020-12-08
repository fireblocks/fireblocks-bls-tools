#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import argparse
import getpass
import sys
from termcolor import colored

from utils import genver

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("BLS_signature_files", type=str, nargs="+", help="space seperated list generated BLS signature files")
    parser.add_argument("-t", "--threshold", type=int, help="check with any subset of this size (if none, check only all)")
    args = parser.parse_args()
    
    for f in args.BLS_signature_files:
        if not os.path.exists(f): 
            print(colored(f'BLS signature file {f} not found.',"cyan"))
            exit(-1)
    
    genver.verify_signature_files(args.BLS_signature_files, args.threshold)

if __name__ == "__main__":
    main()