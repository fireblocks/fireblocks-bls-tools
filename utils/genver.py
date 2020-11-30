from py_ecc.bls import G2Basic as bls_basic
import py_ecc.optimized_bls12_381 as bls_curve
import py_ecc.bls.g2_primatives as bls_conv

import os
import itertools
import secrets
import json

from utils.derivation import *
from typing import Sequence, Dict, Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from termcolor import colored


# Error Handling 

class GenVerErrorBasic(Exception):
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return colored(f'ERROR: {self._msg}', "red")

def sample_random_in_range(range:int):
    val = bls_basic.KeyGen(secrets.token_bytes(48), b'fireblocks_bls_randomness')
    if (val < 2**100):
        raise GenVerErrorBasic(f'Suspicious randomness samples')
    return val % range

# Return shamir secret shares of value, and value also (poly at 0)
def sample_shares(ids: Sequence[int], threshold:int, prime:int) -> Tuple[int, int]:
    
    if len(ids) != len(set(ids)):
        raise GenVerErrorBasic(f'Non-unique ids {ids}')
    
    if threshold > len(ids) or threshold < 1:
        raise GenVerErrorBasic(f'Invalid threhsold {threshold} for ids {ids}')
    
    # Sample polyomial coeffcients of degree threshold-1
    poly_coeff = [0] * threshold
    for i in range(0, threshold):
        poly_coeff[i] = sample_random_in_range(prime)

    # Evaluate (horner's method) on each id
    shares = {id : poly_coeff[threshold-1] for id in ids}
    for i in range(threshold-2, -1, -1):
        for id in shares.keys():
            shares[id] = (shares[id]*id + poly_coeff[i]) % prime

    return shares, poly_coeff[0]


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
def _interpolate_in_group(group_shares:Dict[int,tuple], group_gen:tuple) -> tuple:
    lagrange_coeff = _all_lagrange_coeff_at_point(0, group_shares.keys(), bls_curve.curve_order)
    combined_group_element = bls_curve.multiply(group_gen, 0)
    for id, gr_el in group_shares.items():
        combined_group_element = bls_curve.add(combined_group_element, bls_curve.multiply(gr_el, lagrange_coeff[id]))
    
    return combined_group_element

def _get_test_msg_for_address(pubkey_address:bytes, msg:str=None) -> bytes:
    if msg:
        test_message = bytearray(msg)
    else:
        test_message = bytearray(b'BLS MPC Signing: Fireblocks Approves This Message!')
    test_message.extend(pubkey_address)
    return bytes(test_message)

def _sign_derived_msg(private_key_share:int, private_chaincode_share:int, path:str, pubkey_address:bytes, chaincode_address:bytes, msg:str=None) -> bytes:
    der_private_key = derive_private_child(private_key_share, private_chaincode_share, path, pubkey_address, chaincode_address) 
    der_pubkey_address = bls_basic.SkToPk(der_private_key)
    der_test_msg = _get_test_msg_for_address(pubkey_address, msg)
    return bls_basic.Sign(der_private_key, der_test_msg)

def _verify_derived_sig(signature:bytes, public_key:tuple, public_chaincode:tuple, path:str, pubkey_address:bytes, chaincode_address:bytes, msg:str=None) -> bool:
    der_public_key = derive_public_child(public_key, public_chaincode, path, pubkey_address, chaincode_address)
    der_pubkey_address = bls_conv.G1_to_pubkey(der_public_key)
    der_test_msg = _get_test_msg_for_address(pubkey_address, msg)
    return bls_basic.Verify(der_pubkey_address, der_test_msg, signature)

test_path = "test/0"

# parties: dict{ party_id : RSA_pub_file }
def generate_bls12381_private_shares_with_verification(rsa_key_files:Dict[int,str], threshold:int):

    parties_ids = list(rsa_key_files.keys())
    
    private_key_shares, private_key = sample_shares(parties_ids, threshold, bls_curve.curve_order)
    pubkey_address = bls_basic.SkToPk(private_key)
    public_key = bls_conv.pubkey_to_G1(pubkey_address)
    public_key_shares = {id : bls_conv.pubkey_to_G1(bls_basic.SkToPk(val)) for id, val in private_key_shares.items()}

    private_chaincode_shares, private_chaincode = sample_shares(parties_ids, threshold, bls_curve.curve_order)
    chaincode_address = bls_basic.SkToPk(private_chaincode)
    public_chaincode = bls_conv.pubkey_to_G1(chaincode_address)
    public_chaincode_shares = {id : bls_conv.pubkey_to_G1(bls_basic.SkToPk(val)) for id, val in private_chaincode_shares.items()}

    # Verify all authorized set of keys (threshold size) generate the same public key as above
    for auth_ids in itertools.combinations(parties_ids, threshold):
        curr_public_key = _interpolate_in_group({id : public_key_shares[id] for id in auth_ids}, bls_curve.G1)
        if not bls_curve.eq(public_key, curr_public_key):
            raise GenVerErrorBasic(f'Invalid Shamir secret sharing of public key for parties {auth_ids}')
    
    # Sign test message with each private key share, derived as test path
    signature_shares = {}
    for id in parties_ids:
        try:
            signature_shares = {id : _sign_derived_msg(priv, private_chaincode_shares[id], test_path, pubkey_address, chaincode_address) for id, priv in private_key_shares.items()}
        except Exception as e:
            raise e#GenVerErrorBasic(f'Unable to sign test message for id {id}')

    # Output data to file
    data = {}
    data['master_public_key'] = create_master_public(public_key, public_chaincode).hex()
    data['threshold'] = threshold
    data['parties'] = {}
    for id in parties_ids:
        party = {}
        party['master_public_key_share'] = create_master_public(public_key_shares[id], public_chaincode_shares[id]).hex()
        party['test_signature_share'] = signature_shares[id].hex()
        data['parties'][id] = party
    
    for id, rsa_key_file in rsa_key_files.items():

        # Encrypt private key share
        try:
            rsa_key = RSA.importKey(open(rsa_key_file, 'r').read())
            cipher = PKCS1_OAEP.new(rsa_key)
        except:
            raise GenVerErrorBasic(f'Reading RSA key file {rsa_key_file}')
        try:
            ciphertext = cipher.encrypt(create_master_private(private_key_shares[id], private_chaincode_shares[id]))
        except:
            raise GenVerErrorBasic(f'Unable to encrypt verification data for id {id}')

        data['my_id'] = id
        data['encrypted_master_private_key'] = ciphertext.hex()

        verification_filename = f'id_{id}_fireblocks_bls_key_verification_{pubkey_address[:4].hex()}.json'
        try:
            ver_file = open(verification_filename, 'w+')
            json.dump(data, ver_file, indent=4)
            ver_file.close()
            print("Generated file:", colored(f'{verification_filename}', "green"))
        except ValueError:
            raise GenVerErrorBasic(f'Error writing encrypted private key share for id {id}')

    return pubkey_address

def _hex_to_pubkey(address_hex:str):
    pubkey_address = bytes.fromhex(address_hex)
    if not bls_basic.KeyValidate(pubkey_address):
        raise GenVerErrorBasic(f'Invalid public key adrees {address_hex}')
    return pubkey_address, bls_conv.pubkey_to_G1(pubkey_address)

# Verify  threshold of signature shares from given files can reconstruct verifiable signature on test_message
# If threshold not given, assume all files
# Check sane pubkey in all verificaion files. If None, set from first verification file
def verify_signature_shares(verification_file:str, rsa_priv_key_file:str=None, rsa_passphrase:str=None):
    try:
        in_file = open(verification_file, "r")
        data = json.load(in_file)
        in_file.close()
    except:
        raise GenVerErrorBasic(f'Reading verificaion file {verification_file}')

    print(f'Parsing verification file...')

    try:
        public_key, public_chaincode = parse_master_public(bytes.fromhex(data['master_public_key']))
        threshold = data['threshold']
        my_id = data['my_id']
        parties = data['parties']
        public_key_shares = {}
        pubkey_address_shares = {}
        public_chaincode_shares = {}
        test_signature_shares = {}
        parties_ids = []
        for id_str, party in parties.items():
            id = int(id_str)
            parties_ids.append(id)
            public_key_shares[id], public_chaincode_shares[id] = parse_master_public(bytes.fromhex(party['master_public_key_share']))
            test_signature_shares[id] = bytes.fromhex(party['test_signature_share'])
            pubkey_address_shares[id] = bls_conv.G1_to_pubkey(public_key_shares[id])
    except:
        raise GenVerErrorBasic(f'Error parsing verificaion file')

    pubkey_address = bls_conv.G1_to_pubkey(public_key)
    chaincode_address = bls_conv.G1_to_pubkey(public_chaincode)

    #If Given RSA file Decrypt prviate key, verify corrensponds to public key (same for chaincode)
    decryption_verified = False
    if rsa_priv_key_file: 
        try:
            encrypted_master_private_key_share = bytes.fromhex(data['encrypted_master_private_key'])
        except:
            raise GenVerErrorBasic(f'Error getting encrypted master private key share from file')

        try:
            in_file = open(rsa_priv_key_file, 'r')
            rsa_key = RSA.importKey(in_file.read(), passphrase=rsa_passphrase)
            cipher = PKCS1_OAEP.new(rsa_key)
            in_file.close()
        except:
            raise GenVerErrorBasic(f'Importing RSA key from file {rsa_priv_key_file}')

        if not rsa_key.has_private():
            raise GenVerErrorBasic(f'Not a private RSA key file {rsa_priv_key_file}')

        try:
            master_private_key_share = cipher.decrypt(encrypted_master_private_key_share)
        except:
            raise GenVerErrorBasic(f'Invalid decryption of private key share from verification file')

        my_private_key_share, my_private_chaincode_share = parse_master_private(master_private_key_share)

        my_public_key_share = bls_basic.SkToPk(my_private_key_share)
        my_public_chaincode_share = bls_basic.SkToPk(my_private_chaincode_share)
        
        if not bls_conv.G1_to_pubkey(public_key_shares[my_id]) == my_public_key_share or not bls_conv.G1_to_pubkey(public_chaincode_shares[my_id]) == my_public_chaincode_share:
            raise GenVerErrorBasic(f'Decrypted master private key shares doesn\'t correspond to public' )
        
        decryption_verified = True
    
    # Sanity checks

    if threshold > len(parties_ids) or threshold < 1:
        raise GenVerErrorBasic(f'Invalid threhsold {threshold} for ids {parties_ids}')

    if (len(parties_ids) != len(set(parties_ids))):
        raise GenVerErrorBasic(f'Non-unique ids in verification file')

    # Now, after parsing (either) verificaion file, should have the following
    # public address, threshold, all ids, public keys and signature shares.
    # Verify all are correct

    # Verify al signature shares was signed by corresoponding public key share
    for id in parties_ids:
        if not _verify_derived_sig(test_signature_shares[id], public_key_shares[id], public_chaincode_shares[id], test_path, pubkey_address, chaincode_address):
            raise GenVerErrorBasic(f'Failed verification of pubkey and signature share for id {id}')

    # Convert to group elements to allow interpolation
    try:
        G2_signature_shares = {id : bls_conv.signature_to_G2(val) for id, val in test_signature_shares.items()}
    except:
        raise GenVerErrorBasic('Invalid encoding of public address and signature shares')

    if threshold > len(parties_ids):
        raise GenVerErrorBasic(f'Should input at least threshold {threshold} unique verification files')

    # For each authorized set of the above:
    # Combine public keys and compare to address.
    # Combine signature shares and verify

    print(f'Done.')
    print(f'Verifying signing threshold {threshold} out of {len(parties_ids)} parties...')
    if not decryption_verified:
        print(colored('without verifing private key share', "red"))
    
    for auth_ids in itertools.combinations(parties_ids, threshold):

        auth_pubkey_address = bls_conv.G1_to_pubkey(_interpolate_in_group({id : public_key_shares[id] for id in auth_ids}, bls_curve.G1))
        if pubkey_address != auth_pubkey_address:
            raise GenVerErrorBasic(f'Invalid public key {auth_pubkey_address.hex()} for parties {auth_ids}')
        
        auth_signature = bls_conv.G2_to_signature(_interpolate_in_group({id : G2_signature_shares[id] for id in auth_ids}, bls_curve.G2))
        if not _verify_derived_sig(auth_signature, public_key, public_chaincode, test_path, pubkey_address, chaincode_address):
            raise GenVerErrorBasic(f'Failed verification of combined signature for ids {auth_ids}')
    
    # Verify un-authorized set can't get valid signature (less then threhsold)
    for auth_ids in itertools.combinations(parties_ids, threshold-1):

        auth_pubkey_address = bls_conv.G1_to_pubkey(_interpolate_in_group({id : public_key_shares[id] for id in auth_ids}, bls_curve.G1))
        if pubkey_address == auth_pubkey_address:
            raise GenVerErrorBasic(f'Reconstructed unauthorized public key {auth_pubkey_address.hex()} for parties {auth_ids}')
        
        auth_signature = bls_conv.G2_to_signature(_interpolate_in_group({id : G2_signature_shares[id] for id in auth_ids}, bls_curve.G2))
        if _verify_derived_sig(auth_signature, public_key, public_chaincode, test_path, pubkey_address, chaincode_address):
            raise GenVerErrorBasic(f'Valid signature for unauthorized ids {auth_ids}')

    print(colored("Success!", "green"))
    return True

def get_derived_address(verification_file:str, path) -> bytes:
    try:
        in_file = open(verification_file, "r")
        data = json.load(in_file)
        in_file.close()
    except:
        raise GenVerErrorBasic(f'Reading verificaion file {verification_file}')

    try:
        public_key, public_chaincode = parse_master_public(bytes.fromhex(data['master_public_key']))
    except:
        raise GenVerErrorBasic(f'Error parsing verificaion file')

    # TODO: verify data signature!

    return bls_conv.G1_to_pubkey(derive_public_child(public_key, public_chaincode, path))
