import ecdsa
from Crypto.Hash import SHA256
import hashlib
import base58
import numpy as np
from concurrent.futures import ProcessPoolExecutor, as_completed

def generate_key_pair(secret_exponent):
    private_key = ecdsa.SigningKey.from_secret_exponent(secret_exponent, curve=ecdsa.SECP256k1)
    compressed_public_key = private_key.get_verifying_key().to_string("compressed")
    
    ripemd160_hash = hashlib.new('ripemd160', hashlib.sha256(compressed_public_key).digest()).digest()
    prefixed_public_key_hash = b'\x00' + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(prefixed_public_key_hash).digest()).digest()[:4]
    
    bitcoin_address = base58.b58encode(prefixed_public_key_hash + checksum).decode('utf-8')
    
    return bitcoin_address, private_key, compressed_public_key

def check_and_write_address(bitcoin_address, private_key, compressed_public_key):
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    if bitcoin_address == target_address:
        with open('found.txt', 'a') as found_file:
            found_file.write(f"Найден целевой адрес: {bitcoin_address}\n")
            found_file.write(f"Закрытый ключ: {private_key.to_string().hex()}\n")
        print("Целевой адрес найден!")
        print(f"Закрытый ключ: {private_key.to_string().hex()}")
        print(f"Сжатый открытый ключ: {compressed_public_key.hex()}")
        print(f"Bitcoin-адрес: {bitcoin_address}\n")
        return True
    return False

def generate_key_pairs(start_range, end_range, num_processes):
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(generate_key_pair, secret_exponent) for secret_exponent in np.random.randint(start_range, end_range, num_processes)]
        
        for future in as_completed(futures):
            bitcoin_address, private_key, compressed_public_key = future.result()
            if check_and_write_address(bitcoin_address, private_key, compressed_public_key):
                return

if __name__ == '__main__':
    num_processes = cpu_count()
    start_range = int("0000000000000000000000000000000000000000000000020000000000000000", 16)
    end_range = int("000000000000000000000000000000000000000000000003ffffffffffffffff", 16)

    generate_key_pairs(start_range, end_range, num_processes)

