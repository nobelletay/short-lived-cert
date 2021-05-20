# -*- coding: utf-8 -*-
"""
Created on Tue May 18 22:29:40 2021

@author: galan
"""

import hashlib
from merklelib import MerkleTree

def hashfunc(value):
    return hashlib.sha256(value).hexdigest()

dom_name = input("Enter domain name: ")

file_name = "C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/CA Middle Daemon Storage/Hashlists/" + dom_name + "/hashlist.txt"

hash_file = open(file_name, 'r')


hash_list = []
for line in hash_file:
  hash_list.append(line[:-1])

hash_file.close()

tree = MerkleTree(hash_list, hashfunc)

root = tree.merkle_root


root_file = "C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/CA Storage/Merkle Roots/" + dom_name + "/merkleroot.txt"

text_file = open(root_file, "w")
n = text_file.write(root)
text_file.close()