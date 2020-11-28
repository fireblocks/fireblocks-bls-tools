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
    parser.add_argument("RSA_public_keys", type=str, nargs="+", help="space seperated list of RSA public key files")
    parser.add_argument("-t", "--threshold", type=int, help="minimal number of shares able to reconstruct private key (if none, assume all)")
    args = parser.parse_args()
    
    # Set party ids for each RSA key file (allows duplicate, will get different shares+id)
    # ids shouldn't be more then 255 bits
    rsa_keys = dict()
    print("Setting ids:")
    id = 1
    for f in args.RSA_public_keys:
        if not os.path.exists(f): 
            print(f'RSA key: {f} not found.')
            exit(-1)
        # TODO: open and read rsa_key from file
        rsa_keys[id] = f
        print(f'id: {id}\tfile: {f}')
        id += 1
    
    num_parties = len(rsa_keys)

    # If no threshold arg, set all rsa_keys
    threshold = num_parties
    if args.threshold is not None:
        threshold = args.threshold
        if threshold > num_parties or threshold < 1:
            print(colored(f'Invalid threshold {threshold} for {num_parties} rsa_keys', "cyan"))
            exit(-1)
    
    try:
        bls_pubkey = genver.generate_bls12381_private_shares_with_verification(rsa_keys, threshold)
        print(colored(f'Generated BLS Public Key Address: {bls_pubkey.hex()}', "green"))
    except ValueError:
        print("ValueError")

if __name__ == "__main__":
    main()