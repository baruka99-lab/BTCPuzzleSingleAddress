from fastecdsa import keys, curve
from ellipticcurve.privateKey import PrivateKey
from multiprocessing import cpu_count, Pool
import hashlib
import binascii
import os
import random

def generate_private_key(compressed=True):
    if compressed:
        return hex((random.randrange(1 << 15 - 1) + (1 << 14)) | 0x8000000000000000)[2:].upper().zfill(64)
    else:
        return hex((random.randrange(1 << 15 - 1) + (1 << 14)))[2:].upper().zfill(64)

def private_key_to_public_key(private_key, fastecdsa=True, compressed=True):
    if fastecdsa:
        key = keys.get_public_key(int('0x' + private_key, 0), curve.secp256k1)
        if compressed:
            return '02' if key.y % 2 == 0 else '03' + hex(key.x)[2:].zfill(64)
        else:
            return '04' + (hex(key.x)[2:] + hex(key.y)[2:]).zfill(128)
    else:
        pk = PrivateKey().fromString(bytes.fromhex(private_key))
        if compressed:
            return '02' if pk.publicKey().y() % 2 == 0 else '03' + pk.publicKey().toString().hex()[:64]
        else:
            return '04' + pk.publicKey().toString().hex().upper()

def public_key_to_address(public_key):
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = var.digest()
    digest = hashlib.sha256(var_encoded).digest()
    var_hex = '00' + binascii.hexlify(var_encoded).decode() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count): output.append(alphabet[0])
    return ''.join(output[::-1])

def private_key_to_wif(private_key):
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]): value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = alphabet[mod] + result, div
    result = alphabet[value] + result
    for c in var:
        if c == 0: pad += 1
        else: break
    return alphabet[0] * pad + result

def generate_key_pair(process_id, target_address):
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)
        wif = private_key_to_wif(private_key)

        # Check and write address to file
        check_and_write_address(process_id, public_key, address, private_key, wif, target_address)

def check_and_write_address(process_id, public_key, bitcoin_address, private_key, wif, target_address):
    #print(f"Process {process_id}: Private Key: {private_key}")
    #print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}\n")

    if bitcoin_address == target_address:
        print(f"Process {process_id}: Target Address Found!")
        with open('F13.txt', 'a') as found_file:
            found_file.write(f"Found Target Address: {bitcoin_address}\n")
            found_file.write(f"Private Key (Hex): {private_key}\n")
            found_file.write(f"WIF: {wif}\n")
            found_file.write(f"Public Key: {public_key}\n")
        return True
    return False

if __name__ == '__main__':
    num_processes = cpu_count()
    pool = Pool(num_processes)
    target_address = "1QCbW9HWnwQWiQqVo5exhAnmfqKRrCRsvW"  # Целевой адрес

    # Start each process with a unique identifier
    pool.starmap(generate_key_pair, [(i, target_address) for i in range(num_processes)])

    pool.close()
    pool.join()
