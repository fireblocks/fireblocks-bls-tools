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
`./fb_bls_generate_key.py <list of RSA public keys for all parties (space seperated)> [-t threshold]`

Output:
* Generated BLS12-381 address (to use in eth2.0)
* Table of ids set for each party (corresponding to RSA public keys)
* Generted verficiation files (containing encrypted BLS key shares) for each id
* Public verificaion file, not containing any data about private key shares

### Verification of key shares
`./fb_bls_verify_key.py <verification_file> [RSA_private_key_file | --public] [-a address]`

* Verification that the encrypted BLS private key share can sign a test message (together with threshold of other parties)
* If `--public` (no RSA key file), then just public verificaion of ability to sign, without actually signing
* If `-a address` is not given, then deduces address from verification file
