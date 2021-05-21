# -*- coding: utf-8 -*-
"""
Created on Wed May 19 00:38:21 2021

@author: galan
"""
#!/usr/local/bin/python
import pickle
import hashlib
import merklelib
import sys

def hashfunc(value):
    return hashlib.sha256(value).hexdigest()

print("hello")
proof_path = "../../middle-daemon-website-daemon-storage/Daily Cert Verification/proof.pickle"
with open(proof_path, 'rb') as f:
    proof = pickle.load(f)
    
hash_path = "../storage/Daily Cert Verification/cert_hash.txt"
root_path = "../../middle-daemon-website-daemon-storage/Daily Cert Verification/merkleroot.txt"


with open(hash_path) as f:
    contents = f.readlines()

cert_hash = contents[0]

with open(root_path) as f:
    contents = f.readlines()

root = contents[0]


if (merklelib.verify_leaf_inclusion(cert_hash, proof, hashfunc, root)):
    print("Present certificate is valid")
else:
    print("Present certificate is not valid")