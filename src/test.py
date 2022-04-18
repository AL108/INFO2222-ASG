import hashlib
import sys

x = input("Enter a string to hash: ")
print(hashlib.sha256(x.encode()).hexdigest())

