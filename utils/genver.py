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

def _all_lagrange_coeff_at_point(point:int, ids:Sequence[int], prime:int):
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
def _interpolate_in_group(group_shares:Dict[int,tuple], group_gen:tuple):
    lagrange_coeff = _all_lagrange_coeff_at_point(0, group_shares.keys(), bls_opt.curve_order)
    combined_group_element = bls_opt.multiply(group_gen, 0)
    for id, gr_el in group_shares.items():
        combined_group_element = bls_opt.add(combined_group_element, bls_opt.multiply(gr_el, lagrange_coeff[id]))
    print(lagrange_coeff)
    
    return combined_group_element

# parties: dict{ party_id : RSA_pub_file }
def generate_bls12381_private_shares(rsa_key_files:Dict[int,str], threshold:int, verification_file:str = None):

    ids = list(rsa_key_files.keys())
    
    private_shares = sample_shares(ids, threshold, bls_opt.curve_order)
    pp.pprint(private_shares)
    public_shares = {id : bls_opt.multiply(bls_opt.G1, private_shares[id]) for id in ids}
    pp.pprint(public_shares)
    
    # Generate public key from first authorized set
    public_key = _interpolate_in_group({ids[i] : public_shares[ids[i]] for i in range(threshold)}, bls_opt.G1)
    
    # Verify all authorized set of keys (threshold size) generate the same public key as above
    for auth_ids in itertools.combinations(ids, threshold):
        curr_public_key = _interpolate_in_group({id : public_shares[id] for id in auth_ids}, bls_opt.G1)
        if not bls_opt.eq(public_key, curr_public_key):
            raise GenVerErrorBasic(f'Invalid public key for parties {auth_ids}')
    
    pubkey_address = bls_conv.G1_to_pubkey(public_key)    
    pubkey_address_hex = pubkey_address.hex()
    
    for id, rsa_key_file in rsa_key_files.items():
        try:
            rsa_key = RSA.importKey(open(rsa_key_file, 'r').read())
            cipher = PKCS1_OAEP.new(rsa_key)
        except Exception as e:
            raise GenVerErrorBasic(f'Reading RSA key file {rsa_key_file}')

        # Encode and encrypt: id, private share, (combined) public address
        plaintext = bytearray(id.to_bytes(8, byteorder="big"))
        plaintext.extend(private_shares[id].to_bytes(32, byteorder="big"))
        plaintext.extend(pubkey_address)

        ciphertext = cipher.encrypt(plaintext)
        out_filename = f'id_{id}_bls_private_key_share_address_{pubkey_address_hex}.rsa_enc'
        if os.path.exists(out_filename):
            raise GenVerErrorBasic(f'Will not write on existing file {out_filename}')

        try:
            out_file = open(out_filename, "w+")
            out_file.write(f'{ciphertext.hex()}')
            out_file.close()
        except Exception as e:
            raise GenVerErrorBasic(f'Error writing encrypted private key share for id {id}')
    import math

    #TODO return address (instead of public key)
    return pubkey_address

def get_test_msg_for_address(pubkey_address:bytes) -> bytes:
    test_message = bytearray(b'BLS MPC Signing: Fireblocks Approves This Message!')
    test_message.extend(pubkey_address)
    return bytes(test_message)

# Generate signature share of test_message, using bls_key (rsa encrypted with given private key, and perhapse passphrase)
# Write verification data: id, pubkey share, pubkey address, signature share to verification file
# Later, with threshold amount of such verificaion files, should be able to reconstruct and verity bls signature on test_message
def sign_with_share(rsa_key_file:Sequence[str], bls_key_share_file:Sequence[str], rsa_key_pass:str=None):
    try:
        in_file = open(rsa_key_file, 'r')
        rsa_key = RSA.importKey(in_file.read(), passphrase=rsa_key_pass)
        cipher = PKCS1_OAEP.new(rsa_key)
        in_file.close()
    except ValueError:
        raise GenVerErrorBasic(f'Reading RSA key file {rsa_key_file}')
    
    if not rsa_key.has_private():
        raise GenVerErrorBasic(f'Not a private RSA key file {rsa_key_file}')

    try:
        in_file = open(bls_key_share_file, "r")
        encrypted_data = bytearray.fromhex(in_file.read())
        in_file.close()
    except ValueError:
        raise GenVerErrorBasic(f'Reading BLS key file {bls_key_share_file}')

    try:
        plaintext = cipher.decrypt(encrypted_data)
        id = int.from_bytes(plaintext[:8], byteorder="big")
        priv_key_share = int.from_bytes(plaintext[8:8+32], byteorder="big")
        pubkey_address = plaintext[8+32:8+32+48]
    except ValueError:
        raise GenVerErrorBasic(f'RSA-decrypting BLS key file {bls_key_share_file} using {rsa_key_file}')

    public_key_share = bls_basic.SkToPk(priv_key_share)
    test_msg = get_test_msg_for_address(pubkey_address)
    signature_share = bls_basic.Sign(priv_key_share, test_msg)

    # print(f'Verify myself: {bls_basic.Verify(public_key_share, test_msg, signature_share)}')
    # print(f'id: {id}')
    # print(f'priv key share: {priv_key_share}')
    # print(f'public key share: {public_key_share.hex()}')
    # print(f'test_msg: {test_msg.hex()}')
    # print(f'signature share: {signature_share.hex()}')

    sig_ver_file_name = f'bls_signature_verification_id_{id}_address_{pubkey_address.hex()}.txt'
    try:
        out_file = open(sig_ver_file_name, "w+")
        out_file.write(f'{pubkey_address.hex()}\n')
        out_file.write(f'{id}\n')
        out_file.write(f'{public_key_share.hex()}\n')
        out_file.write(f'{signature_share.hex()}')
        out_file.close()
    except Exception as e:
        raise GenVerErrorBasic(f'Writing signature share file {sig_ver_file_name}')
    
def string_to_pubkey(address_string:str):
    pubkey_address = bytes.fromhex(address_string)
    if not bls_basic.KeyValidate(pubkey_address):
        raise GenVerErrorBasic(f'Invalid public key adrees {address_string}')
    return pubkey_address, bls_conv.pubkey_to_G1(pubkey_address)

# Verify eahc threshold of signature shares from given files can reconstruct verifiable signature on test_message
# If threshold not given, assume all files
# Check sane pubkey in all verificaion files. If None, set from first verification file
def verify_signature_shares(sig_share_files: Sequence[str], threshold:int=None, address_string:str=None):
    if not threshold:
        threshold = len(sig_share_files)
    
    # convert pubkey string to group element
    if address_string:
        try:
            pubkey_address, G1_pubkey_address = string_to_pubkey(address_string)
            test_msg = get_test_msg_for_address(pubkey_address)
        except Exception as e:
            raise GenVerErrorBasic(f'Invalid public key address {address_string}')

    G1_public_key_shares = dict()
    G2_signature_shares = dict()
    for sig_file in sig_share_files:
        try:
            in_file = open(sig_file, "r")
            in_data = in_file.read().splitlines()
            in_file.close()
        except Exception as e:
            raise GenVerErrorBasic(f'Reading verificaion file {sig_file}')

        # Check file's public key is same as given (or set it if n/a)
        if not address_string:
            address_string = in_data[0]
            try:
                pubkey_address, G1_pubkey_address = string_to_pubkey(address_string)
                test_msg = get_test_msg_for_address(pubkey_address)
            except Exception as e:
                raise GenVerErrorBasic(f'Invalid public key address {address_string} in file {sig_file}')

        if address_string != in_data[0]:
            raise GenVerErrorBasic(f'Different public key address in file {sig_file}')

        # Get id
        try:
            id = int(in_data[1])
        except ValueError:
            raise GenVerErrorBasic(f'Invalid share id {in_data[1]} in file {sig_file}')
        
        if id in G1_public_key_shares.keys():
            raise GenVerErrorBasic(f'Duplicate id {id} in file {sig_file}')

        try:
            curr_public_key_share, G1_public_key_shares[id] = string_to_pubkey(in_data[2])
        except Exception as e:
            raise GenVerErrorBasic(f'Invalid public key address share {in_data[2]} in file {sig_file}')
        
        try:
            curr_signature_share = bytes.fromhex(in_data[3])
            G2_signature_shares[id] = bls_conv.signature_to_G2(curr_signature_share)
            bls_conv.subgroup_check(G2_signature_shares[id])
        except Exception as e:
            raise GenVerErrorBasic(f'Invalid signature share in file {sig_file}')
        
        # Verify current sig share was signed by current public key share
        if not bls_basic.Verify(curr_public_key_share, test_msg ,curr_signature_share):
            raise GenVerErrorBasic(f'Failed verification of pubkey and signature share in file {sig_file}')

    if threshold > len(G1_public_key_shares):
        raise GenVerErrorBasic(f'Should input at least threshold {threshold} unique verification files')

    # For each authorized set of the above:
    # Combine public keys and compare to address.
    # Combine signature shares and verify

    for auth_ids in itertools.combinations(G1_public_key_shares.keys(), threshold):

        G1_auth_public_key = _interpolate_in_group({id : G1_public_key_shares[id] for id in auth_ids}, bls_opt.G1)
        if not bls_opt.eq(G1_pubkey_address, G1_auth_public_key):
            raise GenVerErrorBasic(f'Invalid public key for parties {auth_ids}')
        
        G2_auth_signature = _interpolate_in_group({id : G2_signature_shares[id] for id in auth_ids}, bls_opt.G2)
        if not bls_basic.Verify(bls_conv.G1_to_pubkey(G1_auth_public_key), test_msg ,bls_conv.G2_to_signature(G2_auth_signature)):
            raise GenVerErrorBasic(f'Failed verification of combined signature for ids {auth_ids}')

        print(f'Signature verified for ids {list(auth_ids)}')