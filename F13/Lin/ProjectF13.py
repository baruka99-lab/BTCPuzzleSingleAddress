from fastecdsa import keys, curve, ecdsa
from multiprocessing import cpu_count, Pool
import hashlib
import binascii
import random

def generate_private_key():
    return keys.gen_private_key(curve.secp256k1)

def private_key_to_public_key(private_key, compressed=True):
    key = ecdsa.PrivateKey(private_key, curve=curve.secp256k1)
    if compressed:
        return key.get_verifying_key().to_string('compressed').hex()
    else:
        return key.get_verifying_key().to_string('uncompressed').hex()

def public_key_to_address(public_key):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key)
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

def private_key_to_wif(private_key):
    return keys.get_wif(int(private_key, 16), compressed=True, version=0x80)

def generate_key_pair(process_id, target_address, compressed=True):
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key, compressed=compressed)
        address = public_key_to_address(public_key)
        wif = private_key_to_wif(private_key)

        # Check and write address to file
        if check_and_write_address(process_id, public_key, address, private_key, wif, target_address):
            break

def check_and_write_address(process_id, public_key, bitcoin_address, private_key, wif, target_address):
    print(f"Process {process_id}: Private Key: {private_key}")
    print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}\n")

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
    target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP"  # Целевой адрес

    # Start each process with a unique identifier
    pool.starmap(generate_key_pair, [(i, target_address, True) for i in range(num_processes)])

    pool.close()
    pool.join()
