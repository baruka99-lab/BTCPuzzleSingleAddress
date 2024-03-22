import secp256k1 as ice

def generate_and_check_private_key(private_key):
    try:
        wif = ice.btc_pvk_to_wif(private_key)
        public_key = ice.btc_wif_to_pubkey(wif)
        address = ice.btc_pubkey_to_address(public_key)
        if address == '13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so':
            print(f'Private Key: {private_key}')
            print(f'Address: {address}')
            with open("F13.txt", "a") as file:
                file.write(f"Private Key: {private_key}\n")
                file.write(f"Address: {address}\n\n")
        
    except Exception as e:
        print(f"Error occurred for private key {private_key}: {e}")

if __name__ == "__main__":
    start_range = 2**65
    end_range = (2**66) - 1
    
    for private_key in range(start_range, end_range):
        generate_and_check_private_key(private_key)
