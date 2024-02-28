print("Start!")

import ecdsa
import hashlib
import hmac
import base58check
import binascii
import os
from multiprocessing import Process, Manager, cpu_count

def worker(bitcoin_address, key_size, offset, result_dict):
    while True:
        # Decode the Base58Check-encoded bitcoin address
        decoded_address = base58check.b58decode(bitcoin_address)

        # Extract the public key hash from the decoded address
        public_key_hash = decoded_address[1:-4]

        # Reverse the public key hash
        reversed_public_key_hash = public_key_hash[::-1]

        # Pad the reversed public key hash to the key size
        reversed_public_key_hash_padded = reversed_public_key_hash.ljust(key_size // 8, b'\x00')

        # Convert the padded reversed public key hash to an integer
        x_coord = int.from_bytes(reversed_public_key_hash_padded, 'big')

        # Use HMAC to derive the private key with an offset
        key_material = os.urandom(32)
        private_key = hmac.new(key_material, x_coord.to_bytes((key_size // 8), 'big'), hashlib.sha256).digest()
        private_key = int.from_bytes(private_key, 'big') % ecdsa.SECP256k1.order

        # Truncate the private key to 66 bits
        private_key = private_key | (1 << 65)
        private_key = private_key & ((1 << 66) - 1)

        # Generate the public key from the private key
        public_key_point = ecdsa.ecdsa.generator_secp256k1 * private_key
        public_key = ecdsa.VerifyingKey.from_public_point(public_key_point, curve=ecdsa.SECP256k1)

        # Derive the compressed public key
        compressed_public_key = public_key.to_string("compressed")

        # Use the public key to generate the bitcoin address
        sha256_hash = hashlib.sha256(compressed_public_key).digest()
        ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
        network_byte = b"\x00"
        checksum = hashlib.sha256(hashlib.sha256(network_byte + ripemd160_hash).digest()).digest()[:4]
        generated_bitcoin_address = base58check.b58encode(network_byte + ripemd160_hash + checksum).decode("utf-8")

        #print("Private Key:", binascii.hexlify(private_key.to_bytes((key_size // 8), 'big')).decode('utf-8'))
        #print("Compressed Public Key:", binascii.hexlify(compressed_public_key).decode('utf-8'))
        #print("Original Bitcoin Address:", bitcoin_address)
        #print("Generated Bitcoin Address:", generated_bitcoin_address)

        if bitcoin_address == generated_bitcoin_address:
            result_dict['address_found'] = True
            result_dict['original_address'] = bitcoin_address
            result_dict['generated_address'] = generated_bitcoin_address
            result_dict['private_key'] = binascii.hexlify(private_key.to_bytes((key_size // 8), 'big')).decode('utf-8')
            break

if __name__ == '__main__':
    manager = Manager()
    result_dict = manager.dict({'address_found': False})

    bitcoin_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    key_size = 256
    offset = 100

    # Set num_processes to the maximum number of CPU cores
    num_processes = min(cpu_count(), 16)  # Cap at a reasonable number, e.g., 16

    processes = []
    for _ in range(num_processes):
        process = Process(target=worker, args=(bitcoin_address, key_size, offset, result_dict))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    if result_dict['address_found']:
        print("Address Found!")
        print(f"Original Bitcoin Address: {result_dict['original_address']}")
        print(f"Generated Bitcoin Address: {result_dict['generated_address']}")
        print(f"Private Key: {result_dict['private_key']}")

        with open("found.txt", "a") as f:
            f.write(f"Original Bitcoin Address: {result_dict['original_address']}\n")
            f.write(f"Generated Bitcoin Address: {result_dict['generated_address']}\n")
            f.write(f"Private Key: {result_dict['private_key']}\n")
            f.write("\n")
