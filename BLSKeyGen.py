#!/usr/bin/python3

from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls import G2Basic as bls_basic

from typing import Sequence

import time
import logging
import argparse
import sys
import re
import random

PRIME = 10317404450663184820252159349259770959443105916604213719788189125508383084274881469117865728857834322963070209213604674804453131539070913747060765953952221

def share_value(value: int, ids: Sequence[int], threshold:int):
    
    # TODO: check ids are unique
    
    if threshold > len(ids) or threshold < 1:
        print(f'invalid threhsold {threshold} for ids {ids}')
        return
    
    # Sample polyomial coeffcients (decresing indices) of degree threshold-1
    poly_coeff = [0] * threshold
    poly_coeff[threshold-1] = value
    for i in range(threshold-1):
        # TODO: crypto secure random sampling?
        while poly_coeff[i] == 0:
            poly_coeff[i] = random.randrange(PRIME)

    # Evlauate (horner's method) on each id
    shares = {id : poly_coeff[0] for id in ids}
    for i in range(1, threshold):
        for id in shares.keys():
            shares[id] = (poly_coeff[i] + id*shares[id]) % PRIME

    return shares
    
if __name__ == "__main__":
    
    # Parse command line arguments
    num_shares = 3
    threshold = 3
    der_path = 'm/'

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-n", "--num_shares", type=int, default=num_shares, help=" ")
    parser.add_argument("-t", "--threshold", type=int, default=threshold, help=" ")
    parser.add_argument("-p", "--derivation_path", type=str, default=der_path, help=" ")
    args = parser.parse_args()

    num_shares = args.num_shares
    threshold  = args.threshold
    der_path   = args.derivation_path

    root_private = b'udi@fireblocks.io'
    private_key = bls_basic.KeyGen(IKM = root_private, key_info=str.encode(der_path))
    public_key = bls_pop.SkToPk(private_key)

    print(f'root private:\n{root_private}')
    print(f'derived private:\n{private_key}')
    print(f'derived public:\n{public_key}')

    print(f'shares:\n{share_value(int.from_bytes(root_private, "big"), [1, 2, 3], 2)}')

    message = b'Fireblocks has approved this message'

    # Signing
    signature = bls_pop.Sign(private_key, message)

    # Verifying
    assert bls_pop.Verify(public_key, message, signature)