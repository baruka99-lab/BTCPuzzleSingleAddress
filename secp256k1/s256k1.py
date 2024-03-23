import secp256k1 as ice
import hashlib
import base58
import secrets
from bitcoinlib.keys import PrivateKey

def generate_bitcoin_private_key():
    # Generate a random 256-bit integer (private key)
    private_key_int = secrets.randbelow(2**256)
    
    # Convert the private key to WIF format
    wif_private_key = private_key_to_wif(private_key_int.to_bytes(32, 'big'))
    
    # Get the compressed Bitcoin address from the private key
    bitcoin_address = private_key_to_address(private_key_int)
    
    return wif_private_key, bitcoin_address

def private_key_to_wif(private_key_bytes):
    # Adding prefix 0x80 to indicate it is a private key
    extended_key = b'\x80' + private_key_bytes
    
    # Double SHA256 hash
    first_hash = hashlib.sha256(extended_key).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    
    # Get the first 4 bytes of the second hash, this is the checksum
    checksum = second_hash[:4]
    
    # Append the checksum to the extended key
    extended_key += checksum
    
    # Convert the extended key to base58
    wif_private_key = base58.b58encode(extended_key)
    
    return wif_private_key.decode('utf-8')

def private_key_to_address(private_key_int):
    # Create PrivateKey object from integer private key
    private_key = PrivateKey(private_key_int)
    
    # Get the compressed Bitcoin address
    bitcoin_address = private_key.address(compressed=True)
    
    return bitcoin_address

# Example usage:
for _ in range(10):  # Generate 10 random private keys and their corresponding Bitcoin addresses
    private_key, address = generate_bitcoin_private_key()
    print("Private Key:", private_key)
    print("Bitcoin Address:", address)
    print()
