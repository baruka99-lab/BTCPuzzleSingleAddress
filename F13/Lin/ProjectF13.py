import secp256k1 as ice

def generate_and_check_private_key(start_range, end_range, target_address, output_file):
    for i in range(start_range, end_range):
        try:
            address = ice.privatekey_to_address(0, True, i)
            if address == target_address:
                print(f"Private Key: {i}")
                print(f"Address: {address}")
                with open(output_file, "a") as file:
                    file.write(f"Private Key: {i}\n")
                    file.write(f"Address: {address}\n\n")
        except Exception as e:
            print(f"Error occurred for private key {i}: {e}")

if __name__ == "__main__":
    start_range = 2**65
    end_range = (2**66) - 1
    target_address = '13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so'
    output_file = "F13.txt"
    generate_and_check_private_key(start_range, end_range, target_address, output_file)
