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
    parser.add_argument("key_file",type=str, help="RSA encrypted BLS key file")
    parser.add_argument("--RSA", type=str, nargs="?", help="RSA private key file")
    args = parser.parse_args()
    
    if not os.path.exists(args.key_file): 
        print(colored(f'BLS verificaion file {args.key_file} not found.',"cyan"))
        exit(-1)
    
    passphrase = None
    if args.RSA:
        if not os.path.exists(args.RSA): 
            print(colored(f'RSA private key files {args.RSA} not found.', "cyan"))
        passphrase = getpass.getpass(prompt='Please enter RSA private key passphrase:')
    else:
        passphrase = getpass.getpass(prompt='Please enter BLS public key integrity passphrase:')

    genver.verify_key_file(args.key_file, passphrase, args.RSA)    

if __name__ == "__main__":
    main()