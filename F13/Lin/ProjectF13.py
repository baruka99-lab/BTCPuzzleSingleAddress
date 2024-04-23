print(".........................................................................................................")

import os
import hashlib
import random
import time
from fastecdsa import keys, curve
from multiprocessing import cpu_count, Pool

def generate_private_key():
    return hex((random.randrange((1 << 25) - 1) + (1 << 25)))[2:].upper().zfill(64)

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
        output.append(alphabet)
    return ''.join(output[::-1])

def generate_key_pair(process_id, target_address, compressed=True):
    private_key = generate_private_key()
    public_key = private_key_to_public_key(private_key, compressed=compressed)
    address = public_key_to_address(public_key)

    if address == target_address:
        print(f"Process {process_id}: Target Address Found!")
        print(f"Target Address: {address}")
        print(f"Private Key: {private_key}")
        with open('F13.txt', 'a') as found_file:
            found_file.write(f"Found Target Address: {address}\n")
            found_file.write(f"Private Key (Hex): {private_key}\n")
            found_file.write(f"Public Key: {public_key}\n")
        return True
    return False

def baby_step_giant_step(target_address, num_processes):
    pool = Pool(num_processes)
    addresses = []

    for i in range(num_processes):
        pool.apply_async(generate_key_pair, (i, target_address))

    pool.close()
    pool.join()

    for process in pool.imap_unordered(generate_key_pair, [(i, target_address) for i in range(num_processes)]):
        if process:
            addresses.append(process)

    return addresses

if __name__ == '__main__':
    target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP"  # Целевой адрес
    num_processes = cpu_count()

    start_time = time.time()
    addresses = baby_step_giant_step(target_address, num_processes)
    end_time = time.time()

    print(f"Found {len(addresses)} addresses in {end_time - start_time} seconds.")

    for address in addresses:
        print(f"Address: {address}")
