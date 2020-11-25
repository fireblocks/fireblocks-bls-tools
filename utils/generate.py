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
    #TODO change to KeyGen with checking minimal
    val = SystemRandom().randrange(curve_order)
    if (val <= (curve_order >> 32)):
        # TODO: ErrorFishyRandomness
        return 0 
    return val

def sample_shares(ids: Sequence[int], threshold: int):
    
    # TODO: check ids are unique and non-zero
    
    if threshold > len(ids) or threshold < 1:
        print(f'Invalid threhsold {threshold} for ids {ids}')
        return
    
    # Sample polyomial coeffcients of degree threshold-1
    poly_coeff = [0] * threshold
    for i in range(0, threshold):
        poly_coeff[i] = sample_random_in_curve_order()
        print(f'a_{i} = {poly_coeff[i]}')

    # Evaluate (horner's method) on each id
    shares = {id : poly_coeff[threshold-1] for id in ids}
    for i in range(threshold-2, -1, -1):
        for id in shares.keys():
            shares[id] = (shares[id]*id + poly_coeff[i]) % curve_order

    return shares

#TODO encrypt_private_root_share
#TODO derive_private_at_path
#TODO interpolate_public
#TODO public_to_address

# parties: dict{ party_id : RSA_pub_file }
def sample_bs12381_shares_with_verificaion(parties, threshold, verification_file):
    print(parties)
    print(threshold)
    print(curve_order)

    shares = sample_shares(parties.keys(), threshold)
    pp.pprint(shares)

    #TODO encrypt root shares (with id)
    #TODO compute pubkey and sign msg shares (pubkey+dummy)
    #TODO for every auth group, verify same public key, join and verify signature against it
    
    #TODO write to file: public key (maybe address), ids, public shares and their signing shares of msg
    #TODO return address

    return None

#TODO verify_data(address, verification_file_list, RSA_key_file, bls_key_share_file)
    #TODO read all data in verification files (values, check same data: threshold, signature_share, public)
    #TODO verify my decrypted key corresponds to public one verification (if exists, if not, add)
    #TODO verify signing with key gives signed share (if exists - if not, add)
    #TODO for every auth group, verify same pubkey and address, join and verify signature against it