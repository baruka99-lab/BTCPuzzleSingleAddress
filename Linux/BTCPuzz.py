from fastecdsa import keys, curve
from ellipticcurve.privateKey import PrivateKey
import multiprocessing
import hashlib
import binascii
import random

def generate_private_key():
    return format(random.randint(0, 0x1FFFFFF) & 0x01FFFFFF, '05x').upper()

def private_key_to_public_key(private_key, compressed=True):
    if compressed:
        key = keys.get_public_key(int(private_key, 16), curve.secp256k1)
        return '02' + format(key.x, '064x').upper() if key.y % 2 == 0 else '03' + format(key.x, '064x').upper()
    else:
        key = keys.get_public_key(int(private_key, 16), curve.secp256k1)
        return '04' + (format(key.x, '064x').upper() + format(key.y, '064x').upper())

def public_key_to_address(public_key):
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
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

def check_and_write_address(bitcoin_address, private_key, process_id):
    # Проверка на наличие конкретного адреса
    target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP"  # Целевой адрес
    if bitcoin_address == target_address:
        print("Целевой адрес найден!")
        print(f"Процесс {process_id}: Закрытый ключ: {private_key}")
        print(f"Процесс {process_id}: Bitcoin-адрес: {bitcoin_address}\n")
        return True

    return False

def generate_key_pair(process_id):
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key, compressed=True) 
        address = public_key_to_address(public_key)

        if address[-4:] == "TEST":  # Проверка на "TEST" для ускорения процесса
            continue

        print(f"Процесс {process_id}: Закрытый ключ: {private_key}")
        print(f"Процесс {process_id}: Сжатый Bitcoin-адрес: {address}\n")

        if check_and_write_address(address, private_key, process_id):
            break

if __name__ == '__main__':
    num_processes = multiprocessing.cpu_count()
    process_list = []

    for i in range(num_processes):
        process = multiprocessing.Process(target=generate_key_pair, args=(i,))
        process_list.append(process)
        process.start()

    for process in process_list:
        process.join()
