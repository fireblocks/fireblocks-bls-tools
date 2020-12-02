from py_ecc.bls import G2Basic as bls_basic
import py_ecc.optimized_bls12_381 as bls_curve
import py_ecc.bls.g2_primatives as bls_conv

from typing import Tuple
from hashlib import sha512

from termcolor import colored
import random

class DerivationErrorBasic(Exception):
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return colored(f'ERROR: {self._msg}', "red")

def _hash_to_bls_field(data:bytes) -> int:
    # First 256 bits ([0]*32 bytes) are ignored in first hash
    digest = bytes(32) + b'hash_to_bls_field' + data + b'hash_to_bls_field'
    result = bls_curve.curve_order
    while result >= bls_curve.curve_order:
        # Hash previous last 256 bits to get new result
        digest = sha512(digest[32:]).digest()
        result = int.from_bytes(digest[:32], byteorder="big")

    return result

def _derivation_format_hash_input(root_public_address:bytes, public_chaincode_address:bytes, path:bytes) -> bytes:
    return root_public_address + public_chaincode_address + path + b'fb_bls_key_derivation'

def index_to_path(index:int) -> bytes:
    return bytes(f'm/{index}/', 'utf-8')

def parse_master_private_key(master_private_key:bytes) -> Tuple[int, int]:
    if not len(master_private_key) == 70:
        raise DerivationErrorBasic(f'Wrong length master private key, got {len(master_private_key)}, should be 70')
    
    checksum = master_private_key[64:70]
    if sha512(master_private_key[:64]).digest()[:6] != checksum:
        raise DerivationErrorBasic(f'Wrong master private key checksum')

    try:
        private_root = int.from_bytes(master_private_key[:32], byteorder="big")
        private_chaincode = int.from_bytes(master_private_key[32:64], byteorder="big")
    except:
        raise DerivationErrorBasic(f'Parsing master private key to private root key and chaincode')

    if (private_root >= bls_curve.curve_order):
        raise DerivationErrorBasic(f'Private root above curve order')
    
    if (private_chaincode >= bls_curve.curve_order):
        raise DerivationErrorBasic(f'Private chaincode above curve order')
    
    return private_root, private_chaincode

def get_master_private_key(private_root:int, private_chaincode:int) -> bytes:
    if (private_root >= bls_curve.curve_order):
        raise DerivationErrorBasic(f'Private root key above curve order')

    if (private_chaincode >= bls_curve.curve_order):
        raise DerivationErrorBasic(f'Private chaincode above curve order')

    joint = private_root.to_bytes(32, byteorder="big") + private_chaincode.to_bytes(32, byteorder="big")
    return joint + sha512(joint).digest()[:6]

def parse_master_pubkey(master_pubkey:bytes) -> Tuple[tuple,tuple]:
    if not len(master_pubkey) == 102:
        raise DerivationErrorBasic(f'Wrong length master public key too short, got {len(master_pubkey)} bytes, should be 102')
    
    checksum = master_pubkey[96:102]
    if sha512(master_pubkey[:96]).digest()[:6] != checksum:
        raise DerivationErrorBasic(f'Wrong master public key checksum')

    if not bls_basic.KeyValidate(master_pubkey[:48]):
        raise DerivationErrorBasic('Parsing master public key')
    if not bls_basic.KeyValidate(master_pubkey[48:96]):
        raise DerivationErrorBasic('Parsing master public chaincode')
    
    try:
        root_public_key = bls_conv.pubkey_to_G1(master_pubkey[:48])
        public_chaincode = bls_conv.pubkey_to_G1(master_pubkey[48:96])
    except:
        raise DerivationErrorBasic('Parsing master public to root public key and chaincode')

    return root_public_key, public_chaincode

def get_master_pubkey(root_G1:tuple, chaincode_G1:tuple) -> bytes:
    try:
        root_pubkey = bls_conv.G1_to_pubkey(root_G1)
        public_chaincode_address = bls_conv.G1_to_pubkey(chaincode_G1)
    except:
        raise DerivationErrorBasic('Encoding master public key')

    if not bls_basic.KeyValidate(root_pubkey):
        raise DerivationErrorBasic('Encoding public root key')

    if not bls_basic.KeyValidate(public_chaincode_address):
        raise DerivationErrorBasic('Encoding public root chaincode')

    joint = root_pubkey + public_chaincode_address 
    return joint + sha512(joint).digest()[:6]

# If master_pubkey is None, derive it from master_private_key
def derive_private_child(master_private_key_share:bytes, path:bytes, master_pubkey:bytes = None) -> int:
    root_private_key_share, root_private_chaincode_share = parse_master_private_key(master_private_key_share)
    
    if master_pubkey: 
        root_public_key, root_public_chaincode = parse_master_pubkey(master_pubkey)
        root_pubkey_address = bls_conv.G1_to_pubkey(root_public_key)
        public_chaincode_address = bls_conv.G1_to_pubkey(root_public_chaincode)
    else:
        root_pubkey_address = bls_basic.SkToPk(root_private_key_share)
        public_chaincode_address = bls_basic.SkToPk(root_private_chaincode_share)
    
    h = _hash_to_bls_field(_derivation_format_hash_input(root_pubkey_address, public_chaincode_address, path)) 
    derived_private = (root_private_key_share + root_private_chaincode_share * h) % bls_curve.curve_order
    
    return derived_private

# If master_pubkey is None, set as share
def derive_public_child(master_pubkey_share:bytes, path:bytes, master_pubkey:bytes = None) -> tuple:
    if not master_pubkey:
        master_pubkey = master_pubkey_share
        
    root_public_key, root_public_chaincode = parse_master_pubkey(master_pubkey)
    root_pubkey_address = bls_conv.G1_to_pubkey(root_public_key)
    public_chaincode_address = bls_conv.G1_to_pubkey(root_public_chaincode)
    h = _hash_to_bls_field(_derivation_format_hash_input(root_pubkey_address, public_chaincode_address, path)) 

    public_key_share, public_chaincode_share = parse_master_pubkey(master_pubkey_share)
    return bls_curve.add(public_key_share, bls_curve.multiply(public_chaincode_share, h))

def test(path_str:str):
    path = bytes(path_str, 'utf-8')

    x = random.randrange(bls_curve.curve_order)
    a = random.randrange(bls_curve.curve_order)
    master_priv = get_master_private_key(x, a)
    x_path = derive_private_child(master_priv, path)

    print(f'x      = {x}')
    print(f'a      = {a}')
    print(f'x_path = {x_path}')

    X = bls_curve.multiply(bls_curve.G1, x)
    A = bls_curve.multiply(bls_curve.G1, a)
    master_pubkey = get_master_pubkey(X, A)

    X_path = derive_public_child(master_pubkey, path)

    print(f'X      = {bls_conv.G1_to_pubkey(X).hex()}')
    print(f'A      = {bls_conv.G1_to_pubkey(A).hex()}')
    print(f'X_path = {bls_conv.G1_to_pubkey(X_path).hex()}')

    print(f'g^x_path == X_path ? {bls_curve.eq(X_path, bls_curve.multiply(bls_curve.G1, x_path))}')

