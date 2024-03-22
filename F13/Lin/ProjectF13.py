import secp256k1 as ice

def generate_and_check_private_keys(start, end, target_address, output_file):
    with open(output_file, 'a') as f:
        for i in range(start, end):
            private_key = hex(i)[2:]  # Convert to hexadecimal without the '0x' prefix
            address = ice.privatekey_to_address(0, True, i)
            if address == target_address:
                f.write(f"Address: {address}\nPrivate Key: {private_key}\n")
                print(f"Address: {address}\nPrivate Key: {private_key}\n")
                f.flush()  # Flush the buffer to ensure data is written immediately

# 66-bit range
start_range = 2**65
end_range = (2**66) - 1

target_address = '13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so'
output_file = 'F13.txt'

generate_and_check_private_keys(start_range, end_range, target_address, output_file)
