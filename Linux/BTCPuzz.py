print("Начало! Удачи!")

import ecdsa
import hashlib
import base58check
from multiprocessing import Pool, cpu_count
import secrets

TARGET_ADDRESS = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"

def generate_key_pair(process_id):
    while True:
        secret_exponent = secrets.randbelow(2**66 - 2**65) + 2**65
        private_key = ecdsa.SigningKey.from_secret_exponent(secret_exponent, curve=ecdsa.SECP256k1)
        compressed_public_key = private_key.get_verifying_key().to_string("compressed")
        public_key_hash = hashlib.new('ripemd160', hashlib.sha256(compressed_public_key).digest()).digest()
        prefixed_public_key_hash = b'\x00' + public_key_hash
        checksum = hashlib.sha256(hashlib.sha256(prefixed_public_key_hash).digest()).digest()[:4]
        bitcoin_address = base58check.b58encode(prefixed_public_key_hash + checksum).decode('utf-8')

        if check_and_write_address(process_id, compressed_public_key, bitcoin_address, private_key):
            break

def check_and_write_address(process_id, compressed_public_key, bitcoin_address, private_key):
    if bitcoin_address == TARGET_ADDRESS:
        with open('found.txt', 'a') as found_file:
            found_file.write(f"Найден Целевой Адрес: {bitcoin_address}\n")
            found_file.write(f"Приватный Ключ: {private_key.to_string().hex()}\n")
        print(f"Процесс {process_id}: Приватный Ключ: {private_key.to_string().hex()}")
        print(f"Процесс {process_id}: Сжатый Публичный Ключ: {compressed_public_key.hex()}")
        print(f"Процесс {process_id}: Биткоин-Адрес: {bitcoin_address}\n")
        return True

    return False

if __name__ == '__main__':
    num_processes = cpu_count()
    pool = Pool(num_processes)

    pool.map(generate_key_pair, range(num_processes))

    pool.close()
    pool.join()
