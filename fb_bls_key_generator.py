#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import argparse
import getpass
import sys
from termcolor import colored

from utils import recover
from utils import genver

pubkey_descriptions = {
    'MPC_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPUB',
    'MPC_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended public key (Fireblocks format)',
    'MPC_BLS_BLS12381': 'MPC_BLS_BLS12381 extended public key (Fireblocks format)',
}

privkey_descriptions = {
    'MPC_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPRV',
    'MPC_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended private key (Fireblocks format)',
    'MPC_BLS_BLS12381': 'MPC_BLS_BLS12381 extended private key (Fireblocks format)',
}

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

def main():
    parser = argparse.ArgumentParser() #formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("RSA_keys", type=str, nargs="+", help="space seperated list of RSA public key files")
    parser.add_argument("-t", "--threshold", type=int, help="minimal number of shares able to reconstruct private key")
    args = parser.parse_args()
    
    # Set party ids for each RSA key file (allows duplicate, will get different shares+id)
    # ids shouldn't be more then 255 bits
    rsa_keys = dict()
    print("Setting ids:")
    id = 1
    for f in args.RSA_keys:
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
            print(f'Invalid threshold {threshold} for {num_parties} rsa_keys')
            exit(-1)

    try:
        bls_pubkey = genver.sample_bs12381_shares_with_verificaion(rsa_keys, threshold)
    except ValueError:
        print("ValueError")

if __name__ == "__main__":
    main()