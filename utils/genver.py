from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls import G2Basic as bls_basic
import py_ecc.optimized_bls12_381 as bls_opt
import py_ecc.bls.g2_primatives as bls_conv

from typing import Sequence, Dict
from random import SystemRandom
from Crypto.PublicKey import RSA

import os
import itertools
import pprint

from Crypto.Cipher import PKCS1_OAEP
pp = pprint.PrettyPrinter(indent=2)

# Error Handling 

class GenVerErrorBasic(Exception):
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return f'ERROR: {self._msg}'

class GenVerErrorInvalidPublicKeyReconstructed(GenVerErrorBasic):
    pass

class GenVerErrorRSAKeyImport(GenVerErrorBasic):
    pass

class GenVerErrorBLSKeyImport(GenVerErrorBasic):
    pass

class GenVerErrorRSAEncryption(GenVerErrorBasic):
    pass

class GenVerErrorRSADecryption(GenVerErrorBasic):
    pass

# bls_opt.curve_order = 7
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
def generate_bls12381_private_shares(rsa_key_files:Dict[int,str], threshold:int, verification_file:str = None):
    print(rsa_key_files)
    print(threshold)
    print(bls_opt.curve_order)

    ids = list(rsa_key_files.keys())
    
    private_shares = sample_shares(ids, threshold, bls_opt.curve_order)
    pp.pprint(private_shares)
    public_shares = {id : bls_opt.multiply(bls_opt.G1, private_shares[id]) for id in ids}
    pp.pprint(public_shares)
    
    # Generate public key from first authorized set
    public_key = interpolate_public({ids[i] : public_shares[ids[i]] for i in range(threshold)})
    print(public_key)
    
    # Verify all authorized set of keys (threshold size) generate the same public key as above
    for auth_ids in itertools.combinations(ids, threshold):
        print(auth_ids)
        curr_public_key = interpolate_public({id : public_shares[id] for id in auth_ids})
        print(curr_public_key)
        if not bls_opt.eq(public_key, curr_public_key):
            raise GenVerErrorInvalidPublicKeyReconstructed(f'Invalid public key for parties {auth_ids}')
    
    pubkey_address = bls_conv.G1_to_pubkey(public_key)    
    pubkey_address_hex = pubkey_address.hex()
    print(type(pubkey_address), len(pubkey_address))
    for id, rsa_key_file in rsa_key_files.items():
        try:
            rsa_key = RSA.importKey(open(rsa_key_file, 'r').read())
            cipher = PKCS1_OAEP.new(rsa_key)
        except Exception as e:
            raise GenVerErrorRSAKeyImport(f'Reading RSA key file {rsa_key_file}')

        # Encode and encrypt: id, private share, (combined) public address
        plaintext = bytearray(id.to_bytes(8, byteorder="big"))
        plaintext.extend(private_shares[id].to_bytes(32, byteorder="big"))
        plaintext.extend(pubkey_address)

        ciphertext = cipher.encrypt(plaintext)
        out_filename = f'id_{id}_bls_private_key_share_address_{pubkey_address_hex}.rsa_enc'
        if os.path.exists(out_filename):
            raise GenVerErrorRSAEncryption(f'Will not write on existing file {out_filename}')

        try:
            out_file = open(out_filename, "w+")
            out_file.write(f'{ciphertext.hex()}')
            out_file.close()
        except Exception as e:
            raise GenVerErrorRSAEncryption(f'Error writing encrypted private key share for id {id}')
    import math

    #TODO return address (instead of public key)
    return pubkey_address

test_message = b'BLS MPC Signing: Fireblocks Approves This Message!'

def sign_with_share(rsa_key_file, bls_key_share_file, rsa_key_pass=None):
    try:
        in_file = open(rsa_key_file, 'r')
        rsa_key = RSA.importKey(in_file.read(), passphrase=rsa_key_pass)
        cipher = PKCS1_OAEP.new(rsa_key)
        in_file.close()
    except ValueError:
        raise GenVerErrorRSAKeyImport(f'Reading RSA key file {rsa_key_file}')
    
    if not rsa_key.has_private():
        raise GenVerErrorRSAKeyImport(f'Not a private RSA key file {rsa_key_file}')

    try:
        in_file = open(bls_key_share_file, "r")
        encrypted_data = bytearray.fromhex(in_file.read())
        in_file.close()
    except ValueError:
        raise GenVerErrorBLSKeyImport(f'Reading BLS key file {bls_key_share_file}')

    try:
        plaintext = cipher.decrypt(encrypted_data)
        id = int.from_bytes(plaintext[:8], byteorder="big")
        priv_key_share = int.from_bytes(plaintext[8:8+32], byteorder="big")
        pubkey_address = plaintext[8+32:8+32+48]
    except ValueError:
        raise GenVerErrorRSADecryption(f'Error RSA-decrypting BLS key file {bls_key_share_file} using {rsa_key_file}')

    print(f'id: {id}')
    print(f'priv key share: {priv_key_share}')

    test_msg = bytearray(test_message)
    test_msg.extend(pubkey_address)
    signature_share = bls_basic.Sign(priv_key_share, bytes(test_msg))

    sig_ver_file_name = f'bls_signature_verification_id_{id}_address_{pubkey_address.hex()}.txt'
    try:
        out_file = open(sig_ver_file_name, "w+")
        out_file.write(f'{signature_share.hex()}')
        out_file.close()
    except Exception as e:
        raise GenVerErrorSignatureShare(f'Can\'t write signature share file {sig_ver_file}')
    

#TODO verify_data(address, verification_file_list, RSA_key_file, bls_key_share_file)
    #TODO read all data in verification files (values, check same data: threshold, signature_share, public)
    #TODO verify my decrypted key corresponds to public one verification (if exists, if not, add)
    #TODO verify signing with key gives signed share (if exists - if not, add)
    #TODO for every auth group, verify same pubkey and address, join and verify signature against it
    