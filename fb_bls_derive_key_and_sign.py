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
    parser.add_argument("key_file",type=str, help="BLS key verification file")
    parser.add_argument("--index",type=int, help="derivation index", required=True)
    parser.add_argument("--RSA",type=str, help="Private RSA key file")
    parser.add_argument("--sign_msg", type=str, help="Sign message (hex or string) with private key share")
    parser.add_argument("--hex", action='store_true', help="Message is hex encoded, signed as bytes")
    args = parser.parse_args()
    
    if not os.path.exists(args.key_file): 
        print(colored(f'BLS verificaion file {args.key_file} not found.',"cyan"))
        exit(-1)
    
    if args.hex:
        try:
            bytes.fromhex(args.sign_msg)
        except:
            print(colored(f'Invalid hex sign_msg given', "cyan"))
            exit(-1)
    
    passphrase = None
    if args.RSA:
        if not os.path.exists(args.RSA): 
            print(colored(f'RSA private key files {args.RSA} not found.', "cyan"))
        passphrase = getpass.getpass(prompt='Please enter RSA private key passphrase:')
    else:
        if args.sign_msg:
            print(colored(f'To sign a message, must provide RSA private key file', "cyan"))
            exit(-1)

        passphrase = getpass.getpass(prompt='Please enter BLS public key integrity passphrase:')

    genver.derive_address_and_sign(args.key_file, args.index, passphrase, args.RSA, args.sign_msg, args.hex)

if __name__ == "__main__":
    main()