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
    parser = argparse.ArgumentParser() #formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("verification_file",type=str, help="RSA encrypted BLS key verification file")
    parser.add_argument("RSA_private_key", type=str, nargs="?", help="Private RSA key file")
    parser.add_argument("--public", action="store_true", help="Public verification file, without an RSA key")
    args = parser.parse_args()
    
    if (args.public and args.RSA_private_key) or (not args.public and not args.RSA_private_key):
        print(colored(f'Either choose public verification (--public) or enter an RSA private key file.', "cyan"))
        exit(-1)
    
    if not os.path.exists(args.verification_file): 
        print(colored(f'BLS verificaion file {args.verification_file} not found.',"cyan"))
        exit(-1)
    
    rsa_passphrase = None
    if args.RSA_private_key:
        if not os.path.exists(args.RSA_private_key): 
            print(colored(f'RSA private key files {args.RSA_private_key} not found.', "cyan"))
        rsa_passphrase = getpass.getpass(prompt='Please enter RSA private key passphrase (empty for none):')

    genver.verify_signature_shares(args.verification_file, args.RSA_private_key, rsa_passphrase)

if __name__ == "__main__":
    main()