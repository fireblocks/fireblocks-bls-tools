from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls import G2Basic as bls_basic
import py_ecc.optimized_bls12_381 as bls_curve
import py_ecc.bls.g2_primatives as bls_conv
from blspy import G1Element, G2Element, BasicSchemeMPL

import os
import itertools
import secrets
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

def _get_test_msg_for_address(pubkey_address:bytes) -> bytes:
    test_message = bytearray(b'BLS MPC Signing: Fireblocks Approves This Message!')
    test_message.extend(pubkey_address)
    return bytes(test_message)

# parties: dict{ party_id : RSA_pub_file }
def generate_bls12381_private_shares_with_verification(rsa_key_files:Dict[int,str], threshold:int):

    parties_ids = list(rsa_key_files.keys())
    
    private_key_shares, private_key = sample_shares(parties_ids, threshold, bls_curve.curve_order)
    pubkey_address = bls_basic.SkToPk(private_key)
    public_key = bls_conv.pubkey_to_G1(pubkey_address)
    pubkey_address_shares = {id : bls_basic.SkToPk(val) for id, val in private_key_shares.items()}
    public_key_shares = {id : bls_conv.pubkey_to_G1(val) for id, val in pubkey_address_shares.items()}

    # Verify all authorized set of keys (threshold size) generate the same public key as above
    for auth_ids in itertools.combinations(parties_ids, threshold):
        curr_public_key = _interpolate_in_group({id : public_key_shares[id] for id in auth_ids}, bls_curve.G1)
        if not bls_curve.eq(public_key, curr_public_key):
            raise GenVerErrorBasic(f'Invalid Shamir secret sharing of public key for parties {auth_ids}')
    
    # Sign test message with each private key share
    test_msg = _get_test_msg_for_address(pubkey_address)
    signature_shares = {id : bls_basic.Sign(val, test_msg) for id, val in private_key_shares.items()}

    # For public verification file, output address, num ids, threshold, all address shares and signatures
    verification_file_suffix = f'bls_key_verification_address_{pubkey_address[:4].hex()}'

    try:
        verification_filename = f'public_{verification_file_suffix}.fireblocks'
        out_file = open(verification_filename, "w+")
        out_file.write(f'{pubkey_address.hex()}\n')
        out_file.write(f'{len(parties_ids)}\n')
        out_file.write(f'{threshold}\n')
        for id in parties_ids:
            out_file.write(f'{id}\n')
            out_file.write(f'{pubkey_address_shares[id].hex()}\n')
            out_file.write(f'{signature_shares[id].hex()}\n')

        out_file.close()
        print("Generated file:", colored(f'{verification_filename}', "green"))
    except:
        raise GenVerErrorBasic(f'Exporting public verification file')
    
    for id, rsa_key_file in rsa_key_files.items():

        # Encrypt private key share
        try:
            rsa_key = RSA.importKey(open(rsa_key_file, 'r').read())
            cipher = PKCS1_OAEP.new(rsa_key)
        except:
            raise GenVerErrorBasic(f'Reading RSA key file {rsa_key_file}')
        
        try:
            ciphertext = cipher.encrypt(private_key_shares[id].to_bytes(32, byteorder="big"))
        except:
            raise GenVerErrorBasic(f'Unable to encrypt verification data for id {id}')
        
        # Write to file
        try:
            verification_filename = f'id_{id}_{verification_file_suffix}.rsa_enc.fireblocks'
            out_file = open(verification_filename, "w+")
            out_file.write(f'{pubkey_address.hex()}\n')
            out_file.write(f'{len(parties_ids)}\n')
            out_file.write(f'{threshold}\n')

            # First party is encrypted one, rest come later (unencrypted, since only public values)
            out_file.write(f'{id}\n')
            out_file.write(f'{ciphertext.hex()}\n')

            for other_id in parties_ids:
                if other_id == id:
                    continue
                out_file.write(f'{other_id}\n')
                out_file.write(f'{pubkey_address_shares[other_id].hex()}\n')
                out_file.write(f'{signature_shares[other_id].hex()}\n')

            out_file.close()
            print("Generated file:", colored(f'{verification_filename}', "green"))
        except:
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
def verify_signature_shares(verification_file:str, rsa_priv_key_file:str=None, rsa_passphrase:str=None, address_hex:str=None):
    try:
        in_file = open(verification_file, "r")
        in_data = in_file.read().splitlines()
        in_file.close()
    except:
        raise GenVerErrorBasic(f'Reading verificaion file {verification_file}')

    print(f'Parsing verification file...')

    # First line of verification file is pubkey address, verify same if given
    if not address_hex:
        address_hex = in_data[0]
    if in_data[0] != address_hex:
        raise GenVerErrorBasic(f'Mismatched address with verification file')
    try:
        pubkey_address, _ = _hex_to_pubkey(address_hex)
    except:
        raise GenVerErrorBasic(f'Invalid address {address_hex}')

    test_msg = _get_test_msg_for_address(pubkey_address)

    if rsa_priv_key_file:
        # Decrypt private verification file (rsa encrypted, except address above)
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
            num_parties = int(in_data[1])
            threshold   = int(in_data[2])
            my_id       = int(in_data[3])
        except:
            raise GenVerErrorBasic(f'Unable to parse encrypted verification file')

        try:
            priv_key_share = int.from_bytes(cipher.decrypt(bytes.fromhex(in_data[4])), byteorder="big")
        except:
            raise GenVerErrorBasic(f'Invalid decryption of private key share from verification file')
        
        # Set my_id priv key and signature share, then read all others from file
        try:
            pubkey_address_shares = {my_id : bls_basic.SkToPk(priv_key_share)}
            signature_shares = {my_id : bls_basic.Sign(priv_key_share, test_msg)}
        except:
            raise GenVerErrorBasic(f'Invalid public key and signature share')
        
        try:            
            for i in range(num_parties-1):
                other_id = int(in_data[5+3*i])
                pubkey_address_shares[other_id] = bytes.fromhex(in_data[6+3*i])
                signature_shares[other_id] = bytes.fromhex(in_data[7+3*i])
        except:
            raise GenVerErrorBasic(f'Unable to parse other parties verification data')

    else:
        # If not given RSA private key, parse public verification file (no priv key share)
        try:
            num_parties = int(in_data[1])
            threshold   = int(in_data[2])

            pubkey_address_shares = dict()
            signature_shares = dict()
            for i in range(num_parties):
                id = int(in_data[3+3*i])
                pubkey_address_shares[id] = bytes.fromhex(in_data[4+3*i])
                signature_shares[id] = bytes.fromhex(in_data[5+3*i])

        except:
            raise GenVerErrorBasic(f'Unable to parse public verification file')
    
    parties_ids = pubkey_address_shares.keys()
    if num_parties != len(parties_ids):
        raise GenVerErrorBasic(f'Expected {num_parties} ids, found: {parties_ids}')
    
    if threshold > len(parties_ids) or threshold < 1:
        raise GenVerErrorBasic(f'Invalid threhsold {threshold} for ids {parties_ids}')

    if (len(parties_ids) != len(set(parties_ids))):
        raise GenVerErrorBasic(f'Non-unique ids in verification file')

    # Now, after parsing (either) verificaion file, should have the following
    # public address, threshold, all ids, public keys and signature shares.
    # Verify all are correct

    # Verify al signature shares was signed by corresoponding public key share
    for id in parties_ids:
        if not bls_basic.Verify(pubkey_address_shares[id], test_msg ,signature_shares[id]):
            raise GenVerErrorBasic(f'Failed verification of pubkey and signature share for id {id}')

    # Convert to group elements to allow interpolation
    try:
        G1_public_key_shares = {id : bls_conv.pubkey_to_G1(val) for id, val in pubkey_address_shares.items()}
        G2_signature_shares = {id : bls_conv.signature_to_G2(val) for id, val in signature_shares.items()}
    except:
        raise GenVerErrorBasic('Invalid encoding of public address and signature shares')

    if threshold > len(parties_ids):
        raise GenVerErrorBasic(f'Should input at least threshold {threshold} unique verification files')

    # For each authorized set of the above:
    # Combine public keys and compare to address.
    # Combine signature shares and verify

    print(f'Done.')
    print(f'Verifying signing threshold {threshold} out of {num_parties} parties...')

    for auth_ids in itertools.combinations(parties_ids, threshold):

        auth_pubkey_address = bls_conv.G1_to_pubkey(_interpolate_in_group({id : G1_public_key_shares[id] for id in auth_ids}, bls_curve.G1))
        if pubkey_address != auth_pubkey_address:
            raise GenVerErrorBasic(f'Invalid public key {auth_pubkey_address.hex()} for parties {auth_ids}')
        
        auth_signature = bls_conv.G2_to_signature(_interpolate_in_group({id : G2_signature_shares[id] for id in auth_ids}, bls_curve.G2))
        if not bls_basic.Verify(pubkey_address, test_msg , auth_signature):
            raise GenVerErrorBasic(f'Failed verification of combined signature for ids {auth_ids}')
        if not BasicSchemeMPL.verify(G1Element(pubkey_address), test_msg , G2Element(auth_signature)):
            raise GenVerErrorBasic(f'Failed verification of combined signature for ids {auth_ids} (Chia)')
    
    # Verify un-authorized set can't get valid signature (less then threhsold)
    for auth_ids in itertools.combinations(parties_ids, threshold-1):

        auth_pubkey_address = bls_conv.G1_to_pubkey(_interpolate_in_group({id : G1_public_key_shares[id] for id in auth_ids}, bls_curve.G1))
        if pubkey_address == auth_pubkey_address:
            raise GenVerErrorBasic(f'Reconstructed unauthorized public key {auth_pubkey_address.hex()} for parties {auth_ids}')
        
        auth_signature = bls_conv.G2_to_signature(_interpolate_in_group({id : G2_signature_shares[id] for id in auth_ids}, bls_curve.G2))
        if bls_basic.Verify(pubkey_address, test_msg , auth_signature):
            raise GenVerErrorBasic(f'Valid signature for unauthorized ids {auth_ids}')
        if BasicSchemeMPL.verify(G1Element(pubkey_address), test_msg , G2Element(auth_signature)):
            raise GenVerErrorBasic(f'Valid signature for unauthorized ids {auth_ids} (Chia)')

    print(colored("Success!", "green"))
    return True