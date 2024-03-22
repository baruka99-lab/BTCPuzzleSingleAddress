import secp256k1 as ice
from multiprocessing import Pool, cpu_count

def generate_and_check_private_key(private_key):
    address = ice.privatekey_to_address(0, True, private_key)
    if address == target_address:
        return (address, private_key)

def write_to_file(results, output_file):
    with open(output_file, 'a') as f:
        for address, private_key in results:
            f.write(f"Address: {address}\nPrivate Key: {private_key}\n")
            print(f"Address: {address}\nPrivate Key: {private_key}\n")
            f.flush()  # Flush the buffer to ensure data is written immediately

if __name__ == "__main__":
    # 66-bit range
    start_range = 2**65
    end_range = (2**66) - 1
    target_address = '13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so'
    output_file = 'F13.txt'

    pool = Pool(cpu_count())  # Create a pool of worker processes

    # Generate private keys
    private_keys = range(start_range, end_range)

    # Map private keys to the function for generating and checking
    results = pool.map(generate_and_check_private_key, private_keys)

    # Filter out None values (addresses that didn't match the target)
    results = [result for result in results if result is not None]

    # Write results to file
    write_to_file(results, output_file)

    pool.close()
    pool.join()  # Wait for all processes to finish
