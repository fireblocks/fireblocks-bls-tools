from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls import G2Basic as bls_basic

from py_ecc.optimized_bls12_381 import curve_order

# (
#     add,
    
#     final_exponentiate,
#     G1,
#     multiply,
#     neg,
#     pairing,
#     Z1,
#     Z2,
# )

from typing import Sequence
from random import SystemRandom

import pprint
pp = pprint.PrettyPrinter(indent=2)

#curve_order = 7
# Raise error if randomness is too short
def sample_random_in_curve_order():
    val = SystemRandom().randrange(curve_order)
    if (val <= (curve_order >> 32)):
        # TODO: ErrorFishyRandomness
        return 0 
    return val

def share_value(value: int, ids: Sequence[int], threshold: int):
    
    # TODO: check ids are unique and non-zero
    
    if threshold > len(ids) or threshold < 1:
        print(f'Invalid threhsold {threshold} for ids {ids}')
        return
    
    # Sample polyomial coeffcients of degree threshold-1
    poly_coeff = [0] * threshold
    poly_coeff[0] = value
    for i in range(1, threshold):
        poly_coeff[i] = sample_random_in_curve_order()

    # Evaluate (horner's method) on each id
    shares = {id : poly_coeff[threshold-1] for id in ids}
    for i in range(threshold-2, -1, -1):
        for id in shares.keys():
            shares[id] = (shares[id]*id + poly_coeff[i]) % curve_order

    return shares

# parties: dict{ party_id : RSA_pub_file }
def sample_bs12381_shares_with_verificaion(rsa_keys, threshold):
    print(rsa_keys)
    print(threshold)
    print(curve_order)

    parties = dict()
    id = 1
    for f in rsa_keys:
        # TODO: open and read rsa_key from file
        rsa_key = 1
        parties[id] = rsa_key
        id += 1

    # Generate root private key and shares for ids

    root_private_key = sample_random_in_curve_order()
    print(f'root_priavte_key = {root_private_key}')
    shares = share_value(root_private_key, parties.keys(), threshold)

    pp.pprint(shares)

    return None, None