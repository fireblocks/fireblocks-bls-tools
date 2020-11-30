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

def _derivation_format_bytes(public_root_address:bytes, chaincode_address:bytes, path:str) -> bytes:
    return public_root_address + chaincode_address + bytes(path, 'utf-8') + b'fb_bls_key_derivation'

def parse_master_private(master_private_key:bytes) -> Tuple[int, int]:
    if not len(master_private_key) == 64:
        raise DerivationErrorBasic(f'Wrong length master private key, got {len(master_private_key)}, should be 64')
    try:
        private_root = int.from_bytes(master_private_key[:32], byteorder="big")
        private_chaincode = int.from_bytes(master_private_key[32:], byteorder="big")
    except:
        raise DerivationErrorBasic(f'Parsing master private key')

    if (private_root >= bls_curve.curve_order):
        raise DerivationErrorBasic(f'Private root out of curve order')
    
    if (private_chaincode >= bls_curve.curve_order):
        raise DerivationErrorBasic(f'Private chaincode out of curve order')
    
    return private_root, private_chaincode

def create_master_private(private_root:int, private_chaincode:int) -> bytes:
    if (private_root >= bls_curve.curve_order):
        raise DerivationErrorBasic(f'Private root out of curve order')

    if (private_chaincode >= bls_curve.curve_order):
        raise DerivationErrorBasic(f'Private chaincode out of curve order')

    return private_root.to_bytes(32, byteorder="big") + private_chaincode.to_bytes(32, byteorder="big")

def parse_master_public(master_public_key:bytes) -> Tuple[tuple,tuple]:
    if not len(master_public_key) == 96:
        raise DerivationErrorBasic(f'Wrong length master public key too short, got {len(master_public_key)} bytes, should be 96')

    if not bls_basic.KeyValidate(master_public_key[:48]):
        raise DerivationErrorBasic('Parsing master public key')
    if not bls_basic.KeyValidate(master_public_key[48:]):
        raise DerivationErrorBasic('Parsing master public chaincode')
    
    try:
        root_G1 = bls_conv.pubkey_to_G1(master_public_key[:48])
        chaincode_G1 = bls_conv.pubkey_to_G1(master_public_key[48:])
    except:
        raise DerivationErrorBasic('Parsing master public root')

    return root_G1, chaincode_G1

def create_master_public(root_G1:tuple, chaincode_G1:tuple) -> bytes:
    root_pubkey =  bls_conv.G1_to_pubkey(root_G1)
    chaincode_pubkey = bls_conv.G1_to_pubkey(chaincode_G1)

    if not bls_basic.KeyValidate(root_pubkey):
        raise DerivationErrorBasic('Parsing master public key')
    if not bls_basic.KeyValidate(chaincode_pubkey):
        raise DerivationErrorBasic('Parsing master public chaincode')

    return root_pubkey + chaincode_pubkey

def derive_private_child(private_key_share:int, private_chaincode_share:int, path:str, pubkey_address:bytes=None, chaincode_address:bytes=None) -> int:    
    if not pubkey_address:
        pubkey_address = bls_basic.SkToPk(private_key_share)
        chaincode_address = bls_basic.SkToPk(private_chaincode_share)
    
    h = _hash_to_bls_field(_derivation_format_bytes(pubkey_address, chaincode_address, path)) 
    derived_private = (private_key_share + private_chaincode_share * h) % bls_curve.curve_order
    
    return derived_private

def derive_public_child(public_key_share:tuple, public_chaincode_share:tuple, path:str, pubkey_address:bytes=None, chaincode_address:bytes=None) -> tuple:
    if not pubkey_address:
        pubkey_address = bls_conv.G1_to_pubkey(public_key_share)
        chaincode_address = bls_conv.G1_to_pubkey(public_chaincode_share)

    h = _hash_to_bls_field(_derivation_format_bytes(pubkey_address, chaincode_address, path)) 
    return bls_curve.add(public_key_share, bls_curve.multiply(public_chaincode_share, h))

def test(path:str):
    x = random.randrange(bls_curve.curve_order)
    a = random.randrange(bls_curve.curve_order)
    x_path = derive_private_child(x, a, path)

    print(f'x      = {x}')
    print(f'a      = {a}')
    print(f'x_path = {x_path}')

    X = bls_curve.multiply(bls_curve.G1, x)
    A = bls_curve.multiply(bls_curve.G1, a)
    X_path = derive_public_child(X, A, path)

    print(f'X      = {bls_conv.G1_to_pubkey(X).hex()}')
    print(f'A      = {bls_conv.G1_to_pubkey(A).hex()}')
    print(f'X_path = {bls_conv.G1_to_pubkey(X_path).hex()}')

    print(f'g^x_path == X_path ? {bls_curve.eq(X_path, bls_curve.multiply(bls_curve.G1, x_path))}')

