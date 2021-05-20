# -*- coding: utf-8 -*-
"""
Created on Wed May 19 00:21:57 2021

@author: galan
"""

import hashlib
from merklelib import MerkleTree
import pickle

def hashfunc(value):
    return hashlib.sha256(value).hexdigest()

dom_name = input("Enter domain name: ")
day_num = input("Enter day number: ")

file_name = "C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/CA Middle Daemon Storage/Hashlists/" + dom_name + "/hashlist.txt"

hash_file = open(file_name, 'r')

hash_list = []
for line in hash_file:
  hash_list.append(line[:-1])

hash_file.close()

tree = MerkleTree(hash_list, hashfunc)


proof = tree.get_proof(hash_list[int(day_num)-1])

filename = "C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/Website Daemon Storage/Daily Cert Verification/proof.pickle"

with open(filename, 'wb') as f:
    pickle.dump(proof, f)