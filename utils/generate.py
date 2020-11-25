from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls import G2Basic as bls_basic

import py_ecc.optimized_bls12_381 as bls_opt

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

from typing import Sequence, Dict
from random import SystemRandom
import itertools

import pprint
pp = pprint.PrettyPrinter(indent=2)

#bls_opt.curve_order = 7
# Raise error if randomness is too short
def sample_random_in_range(range:int):
    #TODO change to KeyGen with checking minimal
    val = SystemRandom().randrange(range)
    if (val == 0):
        # TODO: ErrorFishyRandomness
        return 0 
    return val

def sample_shares(ids: Sequence[int], threshold: int, prime:int):
    
    # TODO: check ids are unique and non-zero
    
    if threshold > len(ids) or threshold < 1:
        print(f'Invalid threhsold {threshold} for ids {ids}')
        return
    
    # Sample polyomial coeffcients of degree threshold-1
    poly_coeff = [0] * threshold
    for i in range(0, threshold):
        poly_coeff[i] = sample_random_in_range(prime)
        print(f'a_{i} = {poly_coeff[i]}')

    # Evaluate (horner's method) on each id
    shares = {id : poly_coeff[threshold-1] for id in ids}
    for i in range(threshold-2, -1, -1):
        for id in shares.keys():
            shares[id] = (shares[id]*id + poly_coeff[i]) % prime

    return shares

#TODO encrypt_private_root_share
#TODO derive_private_at_path

def _prime_mod_inverse(x:int, prime:int):
    return pow(x, prime-2, prime)

def all_lagrange_coeff_at_point(point:int, ids:Sequence[int], prime:int):
    lagr = dict()
    for curr_id in ids:
        lagr[curr_id] = 1
        for other_id in ids:
            if other_id == curr_id:
                continue
            lagr[curr_id] = (lagr[curr_id] * (point-other_id)) % prime
            lagr[curr_id] = (lagr[curr_id] * _prime_mod_inverse(curr_id-other_id, prime)) % prime
    return lagr

# Combine (interpolates) public keys using ids (from {id, pubkey} dict)
def interpolate_public(public_shares: Dict[int,tuple]):
    lagrange_coeff = all_lagrange_coeff_at_point(0, public_shares.keys(), bls_opt.curve_order)
    combined_public = bls_opt.multiply(bls_opt.G1, 0)
    for id, pub in public_shares.items():
        combined_public = bls_opt.add(combined_public, bls_opt.multiply(pub, lagrange_coeff[id]))
    print(lagrange_coeff)
    
    return combined_public
    
#TODO public_to_address

# parties: dict{ party_id : RSA_pub_file }
def sample_bs12381_shares_with_verificaion(parties:Dict[int,str], threshold:int, verification_file:str = None):
    print(parties)
    print(threshold)
    print(bls_opt.curve_order)

    ids = list(parties.keys())
    
    private_shares = sample_shares(ids, threshold, bls_opt.curve_order)
    pp.pprint(private_shares)
    public_shares = {id : bls_opt.multiply(bls_opt.G1, private_shares[id]) for id in ids}
    pp.pprint(public_shares)
    
    # Generate public key from first authorized set
    public_key = interpolate_public({ids[i] : public_shares[ids[i]] for i in range(threshold)})
    print(public_key)
    
    for auth_ids in itertools.combinations(ids, threshold):
        print(auth_ids)
        curr_public_key = interpolate_public({id : public_shares[id] for id in auth_ids})
        print(curr_public_key)
        if not bls_opt.eq(public_key, curr_public_key):
            print(f'Incorrect public key for ids {auth_ids}')
            return
        
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
    