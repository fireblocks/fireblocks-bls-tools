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
    parser.add_argument("-t", "--threshold", type=int, help="minimal number of shares able to reconstruct private key", required=True)
    args = parser.parse_args()

    # Get passphrase for integrity check
    master_pubkey_integrity_passphrase = ""
    while len(master_pubkey_integrity_passphrase) < 8:
        master_pubkey_integrity_passphrase = getpass.getpass(prompt='Please enter BLS public key integrity passphrase (minimum 8 characters):')


    # Set party ids for each RSA key file (allows duplicate, will get different sahres id)
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
    threshold = args.threshold

    if threshold > num_parties or threshold < 1:
        print(colored(f'Invalid threshold {threshold} for {num_parties} rsa_keys', "cyan"))
        exit(-1)

    genver.generate_bls_key_shares_with_verification(rsa_keys, threshold, master_pubkey_integrity_passphrase)

if __name__ == "__main__":
    main()