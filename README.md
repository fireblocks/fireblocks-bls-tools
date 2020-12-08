# Fireblocks BLS12-381 Key Sharing and Verification Tool

## Installation

* `git clone https://github.com/fireblocks/fb_bls12381_key_tool.git`
* `cd fb_bls12381_key_tool`

### Prerequisites

Key Generation:
* RSA public keys for each entity which should can a BLS key share

Key Share Validation:
* RSA private key (possibly with passphrase)
* Verification file generted during key generation, encrypted with above RSA key

## Running Locally

### Build the utility locally
* install python 3
* install pip 3
* run: `pip3 install -r requirements.txt`

### Generate BLS12-381 key and encrypted shares, with verfication files
`./fb_bls_generate_key.py <list of RSA public keys for all parties (space seperated)> -t <threshold>`

Output:
* Generated BLS12-381 address (to use in eth2.0)
* Table of ids set for each party (corresponding to RSA public keys)
* Generted BLS key json (containing encrypted BLS private key shares) for each id

### Verification of generated key shares
`./fb_bls_verify_key.py <bls_key_json> [--RSA <RSA_private_key_file>]`

* Verification of signature shares on test message can be reconstructed to a valid signature
* If RSA file given, verify test message was signed correctly with BLS private key share.

### Derive a public key (at index), and generate a signature share on a message
`./fb_bls_derive_key_and_sign.py <bls_key_json> --index [--sign_msg --RSA <RSA_private_key_file> [--hex]]`

* Derive a BLS public key (at index from master pubkey).
* If given sign_msg (and RSA private key file), use decrypted BLS private key share to generate signature share on the message
* sign_msg can be given in hexadecimal, and signed as bytes
* Withdrawal credentials are also printed for the derived address

### Verify signature, reconstructed from signature shares
`./fb_bls_verify_signature.py <list of bls_signature_json files (space seperated)> [-t threshold]`

* Verification of signature shares on test message can be reconstructed to a valid signature
* If threshold is given, checks any subset of threshold signature shares can be reconstructed and verifies (otherwise just checks all)
