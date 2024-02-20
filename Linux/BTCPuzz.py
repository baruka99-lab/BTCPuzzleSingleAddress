import ecdsa
from Crypto.Hash import SHA256
import hashlib
import base58
import random
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count

def generate_key_pair(dummy):
    while True:
        secret_exponent = random.SystemRandom().randrange(start_range, end_range + 1)  # Увеличиваем end_range на 1
        private_key = ecdsa.SigningKey.from_secret_exponent(secret_exponent, curve=ecdsa.SECP256k1)
        compressed_public_key = private_key.get_verifying_key().to_string("compressed")
        
        ripemd160_hash = hashlib.new('ripemd160', hashlib.sha256(compressed_public_key).digest()).digest()
        prefixed_public_key_hash = b'\x00' + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(prefixed_public_key_hash).digest()).digest()[:4]
        
        bitcoin_address = base58.b58encode(prefixed_public_key_hash + checksum).decode('utf-8')
        
        print(f"Private Key: {private_key.to_string().hex()}")
        print(f"Compressed Public Key: {compressed_public_key.hex()}")
        print(f"Bitcoin Address: {bitcoin_address}\n")
        
        yield bitcoin_address, private_key, compressed_public_key

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

def generate_key_pairs(num_processes):
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(generate_key_pair, None) for _ in range(num_processes)]
        
        for future in as_completed(futures):
            bitcoin_address, private_key, compressed_public_key = future.result()
            if check_and_write_address(bitcoin_address, private_key, compressed_public_key):
                break

if __name__ == '__main__':
    num_processes = cpu_count()
    start_range = 0
    end_range = 2**66 - 1

    generate_key_pairs(num_processes)
