import secp256k1 as ice
import secrets

def generate_bitcoin_private_key():
    # Generate a random 32-byte number (private key)
    private_key_bytes = secrets.token_bytes(32)
    
    # Convert the private key bytes to an integer
    private_key = int.from_bytes(private_key_bytes, byteorder='big')
    
    # Convert the private key to WIF format
    wif_private_key = ice.btc_pvk_to_wif(private_key)
    
    # Get the Bitcoin address from the private key
    bitcoin_address = ice.privatekey_to_coinaddress(ice.COIN_BTC, 0, True, private_key)
    
    return wif_private_key, bitcoin_address

# Example usage:
for _ in range(10):  # Generate 10 random private keys and their corresponding Bitcoin addresses
    private_key, address = generate_bitcoin_private_key()
    print("Private Key:", private_key)
    print("Bitcoin Address:", address)
    print()
