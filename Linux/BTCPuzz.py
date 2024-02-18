print("Ready, Set, Go!!!")

import ecdsa
import hashlib
import base58
from multiprocessing import Pool, cpu_count
import random

def generate_key_pair(args):
    process_id, start_range, end_range = args
    random_generator = random.SystemRandom()
    
    while True:
        # Generating a random number within the specified range
        secret_exponent = random_generator.randrange(start_range, end_range)

        # Converting the random number to a private key
        private_key = ecdsa.SigningKey.from_secret_exponent(secret_exponent, curve=ecdsa.SECP256k1)

        # Getting the compressed public key
        compressed_public_key = private_key.get_verifying_key().to_string("compressed")

        # Hashing the public key to get the fingerprint
        public_key_hash = hashlib.new('ripemd160', hashlib.sha256(compressed_public_key).digest()).digest()

        # Adding a prefix to the hash (for Bitcoin address)
        prefixed_public_key_hash = b'\x00' + public_key_hash  # 0x00 for the mainnet

        # Calculating the checksum
        checksum = hashlib.sha256(hashlib.sha256(prefixed_public_key_hash).digest()).digest()[:4]

        # Forming the Bitcoin address in base58
        bitcoin_address = base58.b58encode(prefixed_public_key_hash + checksum).decode('utf-8')

        # Checking and writing to the file found.txt or address.txt
        if check_and_write_address(bitcoin_address, private_key, compressed_public_key, process_id):
            # Breaking the loop if the target address is found
            break

def check_and_write_address(bitcoin_address, private_key, compressed_public_key, process_id):
    # Checking for a specific address
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"  # Target address
    if bitcoin_address == target_address:
        # Writing the found address to the file
        with open('found.txt', 'a') as found_file:
            found_file.write(f"Found Target Address: {bitcoin_address}\n")
            found_file.write(f"Private Key: {private_key.to_string().hex()}\n")
        print("Target Address Found!")
        print(f"Process {process_id}: Private Key: {private_key.to_string().hex()}")
        print(f"Process {process_id}: Compressed Public Key: {compressed_public_key.hex()}")
        print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}\n")
        return True

    return False

if __name__ == '__main__':
    num_processes = cpu_count()
    pool = Pool(num_processes)

    # Specified range for generating secret_exponent
    start_range = int("0000000000000000000000000000000000000000000000020000000000000000", 16)
    end_range = int("000000000000000000000000000000000000000000000003ffffffffffffffff", 16)

    # Launching each process with a unique identifier
    pool.map(generate_key_pair, [(i, start_range, end_range) for i in range(num_processes)])

    pool.close()
    pool.join()
