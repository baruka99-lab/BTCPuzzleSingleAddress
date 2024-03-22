print("Start!")

from fastecdsa import keys, curve
from multiprocessing import cpu_count, Pool
import hashlib
import binascii
import random

def generate_private_key():
    while True:
        private_key = hex((random.randrange((1 << 24) - 1) + (1 << 24)))[2:].zfill(64)
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)
        if address.startswith('15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP'):  # Проверяем, начинается ли адрес на "13z"
            return private_key

def private_key_to_public_key(private_key, compressed=True):
    key = keys.get_public_key(int(private_key, 16), curve.secp256k1)
    if compressed:
        return '02' + hex(key.x)[2:].zfill(64) if key.y % 2 == 0 else '03' + hex(key.x)[2:].zfill(64)
    else:
        return '04' + (hex(key.x)[2:].zfill(64) + hex(key.y)[2:].zfill(64))

def public_key_to_address(public_key):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    output = []
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count):
        output.append(alphabet[0])
    return ''.join(output[::-1])

def generate_key_pair(process_id, compressed=True):
    found_results = []  # Хранить найденные результаты в памяти
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key, compressed=compressed)
        address = public_key_to_address(public_key)

        # Append result to the list
        found_results.append((public_key, address, private_key))
        if len(found_results) >= 1000:  # Записывать и выводить результаты порциями
            write_and_print_results(found_results)
            found_results = []

def write_and_print_results(results):
    with open('F13.txt', 'a') as found_file:
        for public_key, address, private_key in results:
            found_file.write(f"Found Address: {address}\n")
            found_file.write(f"Private Key (Hex): {private_key}\n")
            found_file.write(f"Public Key: {public_key}\n")
            found_file.write("\n")
            print(f"Found Address: {address}")
            print(f"Private Key (Hex): {private_key}")
            print(f"Public Key: {public_key}")
            print()

if __name__ == '__main__':
    num_processes = cpu_count()
    pool = Pool(num_processes)

    # Start each process with a unique identifier
    pool.starmap(generate_key_pair, [(i,) for i in range(num_processes)])

    pool.close()
    pool.join()
