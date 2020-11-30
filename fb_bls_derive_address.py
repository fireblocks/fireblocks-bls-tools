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
    parser.add_argument("verification_file",type=str, help="BLS key verification file")
    parser.add_argument("derivation_path",type=str, help="derivation path, any string, example: m/0/1/2")
    parser.add_argument("ECDSA_public_key", type=str, nargs="?", help="Verification data signed under corresponding key")
    parser.add_argument("--sign", action="store_true", help="Sign test message (with private key share)")
    args = parser.parse_args()
    
    if not os.path.exists(args.verification_file): 
        print(colored(f'BLS verificaion file {args.verification_file} not found.',"cyan"))
        exit(-1)
    
    print("Withdrawal Address:", colored(genver.get_derived_address(args.verification_file, args.derivation_path).hex(), "green"))

if __name__ == "__main__":
    main()