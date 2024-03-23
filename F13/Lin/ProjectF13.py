from array import array
from threading import Thread
from fastecdsa import keys, curve
import hashlib
import binascii
import secrets
from multiprocessing import cpu_count

def generate_private_key_decimal():
    return str(secrets.randbits(256))  # Генерация случайного числа

def read_target_addresses(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file]

def private_key_to_public_key(private_key, compressed=True):
    key = keys.get_public_key(int(private_key), curve.secp256k1)
    if compressed:
        return '02' + format(key.x, '064x') if key.y % 2 == 0 else '03' + format(key.x, '064x')
    else:
        return '04' + format(key.x, '064x') + format(key.y, '064x')

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
    output = array('B')
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet.index(alphabet[remainder]))
    for i in range(count):
        output.append(0)
    return ''.join(alphabet[i] for i in output[::-1])

def generate_key_pair(process_id, target_address, compressed=True):
    while True:
        private_key = generate_private_key_decimal()
        public_key = private_key_to_public_key(private_key, compressed=compressed)
        address = public_key_to_address(public_key)

        if check_and_write_address(process_id, public_key, address, private_key, target_address):
       
def check_and_write_address(process_id, public_key, bitcoin_address, private_key, target_address):
    if bitcoin_address == target_address:
        print(f"Process {process_id}: Target Address Found!")
        print(f"Target Address: {bitcoin_address}")
        print(f"Private Key: {private_key}")
        with open('found_addresses.txt', 'a') as found_file:
            found_file.write(f"Found Target Address: {bitcoin_address}\n")
            found_file.write(f"Private Key (Decimal): {private_key}\n")
            found_file.write(f"Public Key: {public_key}\n")
        return True
    return False

if __name__ == '__main__':
    num_threads = cpu_count()
    target_addresses = read_target_addresses("target_addresses.txt")
    
    threads = [Thread(target=generate_key_pair, args=(target_address,)) for target_address in target_addresses]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
