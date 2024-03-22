import secp256k1 as ice

def generate_and_check_private_key(private_key):
    try:
        address_compressed = ice.btc_pvk_to_address(private_key, True)
        address_uncompressed = ice.btc_pvk_to_address(private_key, False)
        
        if address_compressed == '13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so':
            address_p2sh = ice.btc_pvk_to_address(private_key, True, True)
            address_bech32 = ice.btc_pvk_to_address(private_key, True, False)
            
            print('[C]', address_compressed)
            print('[U]', address_uncompressed)
            print('[P2SH]', address_p2sh)
            print('[Bech32]', address_bech32)
            
            with open("F13.txt", "a") as file:
                file.write(f"Private Key: {private_key}\n")
                file.write(f"Address (compressed): {address_compressed}\n")
                file.write(f"Address (uncompressed): {address_uncompressed}\n")
                file.write(f"Address (P2SH): {address_p2sh}\n")
                file.write(f"Address (Bech32): {address_bech32}\n\n")
        
    except Exception as e:
        print(f"Error occurred for private key {private_key}: {e}")

if __name__ == "__main__":
    start_range = 2**65
    end_range = (2**66) - 1
    
    for private_key in range(start_range, end_range):
        generate_and_check_private_key(private_key)
