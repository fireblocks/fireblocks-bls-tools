from py_ecc.bls import G2ProofOfPossession as bls_basic
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
from hashlib import scrypt, sha512, sha256

# Error Handling 

class GenVerErrorBasic(Exception):
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return colored(f'ERROR: {self._msg}', "red")

def _sample_random_in_range(range:int):
    val = bls_basic.KeyGen(secrets.token_bytes(48), b'fireblocks_bls_randomness')
    if (val < 2**100):
        raise GenVerErrorBasic(f'Suspicious randomness samples')
    return val % range

# Return shamir secret shares of value, and also secret value (poly at 0)
def _sample_shares(ids: Sequence[int], threshold:int) -> Tuple[int, int]:
    
    if len(ids) != len(set(ids)):
        raise GenVerErrorBasic(f'Non-unique ids {ids}')
    
    if threshold > len(ids) or threshold < 1:
        raise GenVerErrorBasic(f'Invalid threhsold {threshold} for ids {ids}')
    
    # Sample polyomial coeffcients of degree threshold-1
    poly_coeff = [0] * threshold
    for i in range(0, threshold):
        poly_coeff[i] = _sample_random_in_range(bls_curve.curve_order)

    # Evaluate (Horner's method) on each id
    shares = {id : poly_coeff[threshold-1] for id in ids}
    for i in range(threshold-2, -1, -1):
        for id in shares.keys():
            shares[id] = (shares[id]*id + poly_coeff[i]) % bls_curve.curve_order

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

# Combine (interpolates) public keys using ids (from {id : public_key} dict)
def _interpolate_in_group(group_shares:Dict[int,tuple], group_gen:tuple) -> tuple:
    lagrange_coeff = _all_lagrange_coeff_at_point(0, group_shares.keys(), bls_curve.curve_order)
    combined_group_element = bls_curve.multiply(group_gen, 0)
    for id, gr_el in group_shares.items():
        combined_group_element = bls_curve.add(combined_group_element, bls_curve.multiply(group_shares[id], lagrange_coeff[id]))
    
    return combined_group_element

# Concatenate pubkey_address string to msg (default msg if not given)
def _get_msg_for_address(pubkey_address:bytes, msg:str=None) -> Tuple[bytes,str]:
    if msg:
        test_message = msg
    else:
        test_message = 'BLS MPC Signing: Fireblocks Approves This Message!'
    test_message = test_message + "_" + pubkey_address.hex()
    return bytes(test_message, 'ascii'), test_message

def _compute_scrypt_checksum(scrypt_key:bytes, salt_to_hash:bytes) -> bytes:
    salt = sha512(salt_to_hash).digest()
    return scrypt(scrypt_key, salt=salt, n=65536, r=16, p=16, maxmem=2**30)

def _get_test_path():
    return b'test/0'

# RSA_key_files: dict{ party_id : RSA_pub_file }
def generate_bls_key_shares_with_verification(rsa_key_files:Dict[int,str], threshold:int, integrity_passphrase:str):

    parties_ids = list(rsa_key_files.keys())

    # Generate and Shamir secret share root private key with related public keys and shares
    root_private_key_shares, root_private_key = _sample_shares(parties_ids, threshold)
    root_public_key = bls_conv.pubkey_to_G1(bls_basic.SkToPk(root_private_key))
    root_public_key_shares = {id : bls_conv.pubkey_to_G1(bls_basic.SkToPk(val)) for id, val in root_private_key_shares.items()}

    # Generate and Shamir secret share private chaincode with related public chaincode
    private_chaincode_shares, private_chaincode = _sample_shares(parties_ids, threshold)
    public_chaincode = bls_conv.pubkey_to_G1(bls_basic.SkToPk(private_chaincode))

    # Set master public key and private key shares
    master_pubkey = get_master_pubkey(root_public_key, public_chaincode)
    master_private_key_shares = {id : get_master_private_key(root_private_key_shares[id], private_chaincode_shares[id]) for id in parties_ids}

    # Senity check: verify all authorized set of keys (threshold size) generate the same root public key as above
    for auth_ids in itertools.combinations(parties_ids, threshold):
        curr_public_key = _interpolate_in_group({id : root_public_key_shares[id] for id in auth_ids}, bls_curve.G1)
        if not bls_curve.eq(root_public_key, curr_public_key):
            raise GenVerErrorBasic(f'Invalid Shamir secret sharing of public key for parties {auth_ids}')
    
    # Sign test message with each private key share, derived at test path
    test_derivation_path = _get_test_path()
    derived_pubkey_address = bls_conv.G1_to_pubkey(derive_public_child(master_pubkey, _get_test_path()))
    signature_shares = {}
    for id in parties_ids:
        try:
            derived_private_key_share = derive_private_child(master_private_key_shares[id], test_derivation_path, master_pubkey)             
            test_msg, _ = _get_msg_for_address(derived_pubkey_address)
            signature_shares[id] = bls_basic.Sign(derived_private_key_share, test_msg)
        except:
            raise GenVerErrorBasic(f'Unable to sign test message for id {id}')
    
    # Scrypt checksum of public key - to avoid manipulation and brute-force
    integrity_passphrase = bytes(integrity_passphrase,'utf-8')
    scrypt_checksum = _compute_scrypt_checksum(integrity_passphrase, master_pubkey)

    # Encrypt master private key shares and (common) integrity passphrase
    encrypted_master_private_key_shares = {}
    encrypted_integrity_passphrase = {}
    for id, rsa_key_file in rsa_key_files.items():
        try:
            rsa_key = RSA.importKey(open(rsa_key_file, 'r').read())
            cipher = PKCS1_OAEP.new(rsa_key)
        except:
            raise GenVerErrorBasic(f'Reading RSA key file {rsa_key_file}')

        if rsa_key.n.bit_length() < 4096:
            GenVerErrorBasic(f'RSA key is too short: {rsa_key.n.bit_length()}, should be at least 4096 bits')

        try:
            encrypted_master_private_key_shares[id] = cipher.encrypt(master_private_key_shares[id])
            encrypted_integrity_passphrase[id] = cipher.encrypt(integrity_passphrase)
        except:
            raise GenVerErrorBasic(f'Unable to encrypt master private key share for id {id}')
        
    # Prepare data to output to file
    
    data = {}
    data['master_pubkey'] = master_pubkey.hex()

    # Ingerity check for master public key
    data['integrity_checksum'] = scrypt_checksum.hex()

    data['threshold'] = threshold
    data['parties'] = {}
    for id in parties_ids:
        party = {}
        party['test_signature_share'] = signature_shares[id].hex()
        party['encrypted_master_private_key_share'] = encrypted_master_private_key_shares[id].hex()
        party['encrypted_integrity_passphrase'] = encrypted_integrity_passphrase[id].hex()
        data['parties'][id] = party
    
    # Output file for each party id (key id)
    for id in parties_ids:
        data['key_id'] = id
        # Write to file
        key_filename = f'id_{id}_fireblocks_bls_key_{master_pubkey[:4].hex()}.json'
        try:
            ver_file = open(key_filename, 'w+')
            json.dump(data, ver_file, indent=4)
            ver_file.close()
            print("Generated file:", colored(f'{key_filename}', "green"))
        except ValueError:
            raise GenVerErrorBasic(f'Error writing key file for id {id}')

    return master_pubkey

# Verify threshold of signature shares of test message existing in the key_file
# passphrase is either for integrity checksum or RSA private key (which decrypts integrity checksum)
def verify_key_file(key_file:str, passphrase:str, rsa_priv_key_file:str=None):
    try:
        in_file = open(key_file, "r")
        data = json.load(in_file)
        in_file.close()
    except:
        raise GenVerErrorBasic(f'Reading key file {key_file}')

    try:
        master_pubkey = bytes.fromhex(data['master_pubkey'])
        integrity_checksum = bytes.fromhex(data['integrity_checksum'])

        threshold = data['threshold']
        my_id = data['key_id']
        parties = data['parties']

        encrypted_private_key_share = bytes.fromhex(parties[f'{my_id}']['encrypted_master_private_key_share'])
        encrypted_integrity_passphrase = bytes.fromhex(parties[f'{my_id}']['encrypted_integrity_passphrase'])

        parties_ids = []
        test_signature_shares = {}
        for id_str, party in parties.items():
            try:
                id = int(id_str)
            except:
                raise GenVerErrorBasic(f'Invalid id {id_str}')
            parties_ids.append(id)
            test_signature_shares[id] = bytes.fromhex(party['test_signature_share'])
        
    except:
        raise GenVerErrorBasic(f'Error parsing key file')

    # If Given RSA private key, use it to get integrity passphrase (if no file, assume integrity passphrase is given)
    master_private_key_share = None
    if rsa_priv_key_file is None:
        integrity_passphrase = bytes(passphrase, 'utf-8')
    else: 
        try:
            in_file = open(rsa_priv_key_file, 'r')
            rsa_key = RSA.importKey(in_file.read(), passphrase=passphrase)
            cipher = PKCS1_OAEP.new(rsa_key)
            in_file.close()
        except:
            raise GenVerErrorBasic(f'Importing RSA key from file {rsa_priv_key_file} (perhaps wrong passphrase)')

        if not rsa_key.has_private():
            raise GenVerErrorBasic(f'Not a private RSA key file {rsa_priv_key_file}')
        
        try:
            master_private_key_share = cipher.decrypt(encrypted_private_key_share)
        except:
            raise GenVerErrorBasic(f'Invalid decryption of private key share from key file')
            
        try:
            integrity_passphrase = cipher.decrypt(encrypted_integrity_passphrase)
        except:
            raise GenVerErrorBasic(f'Invalid decryption of integrity passphrase from key file')

    # Sanity checks

    if threshold > len(parties_ids) or threshold < 1:
        raise GenVerErrorBasic(f'Invalid threhsold {threshold} for ids {parties_ids}')

    if (len(parties_ids) != len(set(parties_ids))):
        raise GenVerErrorBasic(f'Non-unique ids in verification file')
    
    test_derivation_path = _get_test_path()
    derived_public_key = derive_public_child(master_pubkey, test_derivation_path)
    derived_pubkey_address = bls_conv.G1_to_pubkey(derived_public_key)
    test_msg, _ = _get_msg_for_address(derived_pubkey_address)

    # If decrypted master_private_key Verify my own signature wasn't modified by signing again
    if master_private_key_share:
        derived_private_key_share = derive_private_child(master_private_key_share, test_derivation_path, master_pubkey)
        if not test_signature_shares[my_id] == bls_basic.Sign(derived_private_key_share, test_msg):
            raise GenVerErrorBasic(f'Modified signature share for my key id {my_id}')
    else:
        print(colored('No RSA key - not verifying private key share validity!', "cyan"))
    
    # After getting scrypt integrity passphrase validate master pubkey wasn't changed
    computed_checksum = _compute_scrypt_checksum(integrity_passphrase, master_pubkey)

    if not computed_checksum == integrity_checksum:
        raise GenVerErrorBasic(f'Failure in validating master public key integrity checksum (perhaps wrong passphrase)')

    # Convert to group elements to allow interpolation of signatures
    G2_signature_shares = {}
    for id, sig in test_signature_shares.items():
        try:
            G2_signature_shares[id] = bls_conv.signature_to_G2(sig)
        except:
            raise GenVerErrorBasic(f'Invalid encoding of signature shares for id {id}')

    # For each authorized set of the above, combine signature shares and verify

    print(f'Verifying signing threshold {threshold} out of {len(parties_ids)} parties...')
    
    for auth_ids in itertools.combinations(parties_ids, threshold):
        auth_signature = bls_conv.G2_to_signature(_interpolate_in_group({id : G2_signature_shares[id] for id in auth_ids}, bls_curve.G2))
        if not  bls_basic.Verify(derived_pubkey_address, test_msg, auth_signature):
            raise GenVerErrorBasic(f'Failed verification of combined signature for ids {auth_ids}')
    
    # Sanity check: check un-authorized set can't get valid signature (less then threhsold) 
    for auth_ids in itertools.combinations(parties_ids, threshold-1):        
        auth_signature = bls_conv.G2_to_signature(_interpolate_in_group({id : G2_signature_shares[id] for id in auth_ids}, bls_curve.G2))
        if bls_basic.Verify(derived_pubkey_address, test_msg, auth_signature):
            raise GenVerErrorBasic(f'Valid signature for unauthorized ids {auth_ids}')

    print(colored("Success!", "green"))
    return True

def _withdrawal_credentials(withdrawal_pubkey_address:bytes) -> bytes:
        withdrawal_credentials = bytes.fromhex('00')
        withdrawal_credentials += sha256(withdrawal_pubkey_address).digest()[1:]
        return withdrawal_credentials

# pessphrase and rsa_key relation as above
def derive_address_and_sign(key_file:str, derivation_index:int, passphrase:str, rsa_priv_key_file:str=None, sign_msg:str=None, hex_msg:bool=False):
    try:
        in_file = open(key_file, "r")
        in_data = json.load(in_file)
        in_file.close()
    except:
        raise GenVerErrorBasic(f'Reading key file {key_file}')
    
    try:
        master_pubkey = bytes.fromhex(in_data['master_pubkey'])
        integrity_checksum = bytes.fromhex(in_data['integrity_checksum'])
        my_id = in_data['key_id']
        parties = in_data['parties']
        encrypted_integrity_passphrase = bytes.fromhex(parties[f'{my_id}']['encrypted_integrity_passphrase'])
        if sign_msg:
            encrypted_private_key_share = bytes.fromhex(parties[f'{my_id}']['encrypted_master_private_key_share'])
    except:
        raise GenVerErrorBasic(f'Error parsing key file')

    # If Given RSA private key, use it to decrypt integrity passphrase (if no file, assume integrity passphrase is given)
    if rsa_priv_key_file is None:
        integrity_passphrase = bytes(passphrase, 'utf-8')
    else: 
        try:
            in_file = open(rsa_priv_key_file, 'r')
            rsa_key = RSA.importKey(in_file.read(), passphrase=passphrase)
            cipher = PKCS1_OAEP.new(rsa_key)
            in_file.close()
        except:
            raise GenVerErrorBasic(f'Importing RSA key from file {rsa_priv_key_file} (perhaps wrong passphrase)')

        if not rsa_key.has_private():
            raise GenVerErrorBasic(f'Not a private RSA key file {rsa_priv_key_file}')
        
        try:
            integrity_passphrase = cipher.decrypt(encrypted_integrity_passphrase)
        except:
            raise GenVerErrorBasic(f'Invalid decryption of integrity passphrase from key file')

        if sign_msg:
            try:
                master_private_key_share = cipher.decrypt(encrypted_private_key_share)
            except:
                raise GenVerErrorBasic(f'Invalid decryption of BLS private key share')

    # After getting scrypt integrity passphrase validate master pubkey wasn't changed
    computed_checksum = _compute_scrypt_checksum(integrity_passphrase, master_pubkey)

    if not computed_checksum == integrity_checksum:
        raise GenVerErrorBasic(f'Failure in validating master public key integrity checksum (perhaps wrong passphrase)')
    
    # Derive address at index
    
    derivation_path = index_to_path(derivation_index)
    derived_public_key = derive_public_child(master_pubkey, derivation_path)
    derived_pubkey_address = bls_conv.G1_to_pubkey(derived_public_key)

    # Sign message (and write to file) if given
    out_data = {}
    if sign_msg:
        derived_private_key_share = derive_private_child(master_private_key_share, derivation_path, master_pubkey)

        if hex_msg:
            msg_str = sign_msg
            msg_bytes = bytes.fromhex(msg_str)
        else:
            msg_bytes, msg_str = _get_msg_for_address(derived_pubkey_address, sign_msg)

        out_data['master_pubkey'] = master_pubkey.hex()
        out_data['signer_id'] = my_id
        out_data['message'] = {'payload' : msg_str, 'hex' : hex_msg}
        out_data['derivation_index'] = derivation_index
        out_data['signature'] = bls_basic.Sign(derived_private_key_share, msg_bytes).hex()
        
        # Write to file
        sig_filename = f'id_{my_id}_bls_signature_share_{sha512(msg_bytes).digest()[:4].hex()}_{derived_pubkey_address[:4].hex()}_index_{derivation_index}.json'
        try:
            sig_file = open(sig_filename, 'w+')
            json.dump(out_data, sig_file, indent=4)
            sig_file.close()
            print("Message:", colored(f'{msg_str}', "green"))
            print("Generated Signature File:", colored(f'{sig_filename}', "green"))
        except ValueError:
            raise GenVerErrorBasic(f'Error writing signature file for id {id}')
    
    print("Generated Address:", colored(derived_pubkey_address.hex(), "green"))
    print("( Withdrawl Credentials:", colored(_withdrawal_credentials(derived_pubkey_address).hex(), "green"), ")")
    return

def verify_signature_files(signature_files:Sequence[str], threshold:int=None) -> bool:
    
    # Get data from signature share file
    
    parties_ids = []
    signature_shares = {}
    master_pubkey = None
    msg = None
    derivation_index = None
    for sig_file in signature_files:
        in_data = {}
        try:
            in_file = open(sig_file, "r")
            in_data = json.load(in_file)
            in_file.close()
        except:
            raise GenVerErrorBasic(f'Reading key file {sig_file}')
            
        try:
            # Verify same master pubkey
            curr_master_pubkey = bytes.fromhex(in_data['master_pubkey'])
            if master_pubkey:
                if not master_pubkey == curr_master_pubkey:
                    raise GenVerErrorBasic(f'Different master pubkey in different files')
            else:
                master_pubkey = curr_master_pubkey

            # Verify same message
            curr_msg = in_data['message']
            if msg:
                if not msg == curr_msg:
                    raise GenVerErrorBasic(f'Different messages in different files')
            else:
                msg = curr_msg

            # Verify same derivation indx
            curr_index = in_data['derivation_index']
            if derivation_index:
                if not derivation_index == curr_index:
                    raise GenVerErrorBasic(f'Different derivation index in different files')
            else:
                derivation_index = curr_index

            curr_id = int(in_data['signer_id'])
            parties_ids.append(curr_id)
            signature_shares[curr_id] = bytes.fromhex(in_data['signature'])
        except:
            raise GenVerErrorBasic(f'Parsing key file {sig_file}')

    msg_str = msg['payload']
    if msg['hex']:
        try:
            msg_bytes = bytes.fromhex(msg['payload'])
        except:
            raise GenVerErrorBasic(f'Message string is not hex')
    else:
        msg_bytes = bytes(msg_str, 'ascii')
    
    # Convert signature shares to G2 elements to later interpolate on
    G2_signature_shares = {}
    for id, sig in signature_shares.items():
        try:
            G2_signature_shares[id] = bls_conv.signature_to_G2(sig)
        except:
            raise GenVerErrorBasic(f'Invalid encoding of signature for id {id}')
        
    if not threshold:
        threshold = len(parties_ids)

    der_path = index_to_path(derivation_index)
    derived_pubkey_address = bls_conv.G1_to_pubkey(derive_public_child(master_pubkey, der_path))
    
    print(f'Verifying signing threshold {threshold} out of {len(parties_ids)} parties')
    print("Message:", colored(msg_str, "green"))
    print("Public Key:", colored(derived_pubkey_address.hex(), "green"))
    
    # Verify joining threshold singature shares gives a valid signature
    auth_signature = b''
    for auth_ids in itertools.combinations(parties_ids, threshold):
        auth_signature = bls_conv.G2_to_signature(_interpolate_in_group({id : G2_signature_shares[id] for id in auth_ids}, bls_curve.G2))

        if not bls_basic.Verify(derived_pubkey_address, msg_bytes, auth_signature):
            raise GenVerErrorBasic(f'Failed verification of combined signature for id {auth_ids}.')
    
    print("Signature:", colored(auth_signature.hex(), "green"))
    print(colored("Success!", "green"))
    
    return True
