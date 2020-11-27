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
    parser.add_argument("verification_files",type=str,  nargs="+", help="space seperated list of signature share files generates by each party")
    parser.add_argument("-t", "--threshold", type=int, help="minimal number of shares able to reconstruct private key (if none, assume all)")
    parser.add_argument("-a", "--address", type=str, help="BLS public key address (if none, deduce from share files)")
    args = parser.parse_args()
    
    for sig_file in args.verification_files:
        if not os.path.exists(sig_file): 
            print(f'Signature Share Verificaion file {sig_file} not found.')
            exit(-1)

    genver.verify_signature_shares(args.verification_files, args.threshold, args.address)

if __name__ == "__main__":
    main()