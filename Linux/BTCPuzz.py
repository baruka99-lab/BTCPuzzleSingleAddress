print("Start! Good Luck!")

from fastecdsa import keys, curve
from ellipticcurve.privateKey import PrivateKey
import platform
import multiprocessing
import hashlib
import binascii
import os
import sys

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key, fastecdsa):
    if fastecdsa:
        key = keys.get_public_key(int('0x' + private_key, 0), curve.secp256k1)
        return '04' + (hex(key.x)[2:] + hex(key.y)[2:]).zfill(128)
    else:
        pk = PrivateKey().fromString(bytes.fromhex(private_key))
        return '04' + pk.publicKey().toString().hex().upper()

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
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]): value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for c in var:
        if c == 0: pad += 1
        else: break
    return chars[0] * pad + result

def main(database, args):
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key, args['fastecdsa']) 
        address = public_key_to_address(public_key)

        if args['verbose']:
            print(address)
        
        if address[-args['substring']:] in database:
            for filename in os.listdir(DATABASE):
                with open(DATABASE + filename) as file:
                    if address in file.read():
                        with open('plutus.txt', 'a') as plutus:
                            plutus.write('hex private key: ' + str(private_key) + '\n' +
                                         'WIF private key: ' + str(private_key_to_wif(private_key)) + '\n'
                                         'public key: ' + str(public_key) + '\n' +
                                         'uncompressed address: ' + str(address) + '\n\n')
                        break

        #print(f"Process {process_id}: Private Key: {private_key.to_string().hex()}")
        #print(f"Process {process_id}: Compressed Public Key: {compressed_public_key.hex()}")
        #print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}\n")

        # Проверка и запись в файл found.txt или address.txt
        if check_and_write_address(bitcoin_address, private_key, compressed_public_key, process_id):
            # Прерывание цикла, если найден целевой адрес
            break

def check_and_write_address(bitcoin_address, private_key, compressed_public_key, process_id):
    # Проверка на наличие конкретного адреса
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"  # Целевой адрес
    if bitcoin_address == target_address:
        # Запись найденного адреса в файл
        with open('found.txt', 'a') as found_file:
            found_file.write(f"Найден целевой адрес: {bitcoin_address}\n")
            found_file.write(f"Закрытый ключ: {private_key.to_string().hex()}\n")
        print("Целевой адрес найден!")
        print(f"Процесс {process_id}: Закрытый ключ: {private_key.to_string().hex()}")
        print(f"Процесс {process_id}: Сжатый открытый ключ: {compressed_public_key.hex()}")
        print(f"Процесс {process_id}: Bitcoin-адрес: {bitcoin_address}\n")
        return True

    return False

if __name__ == '__main__':
    num_processes = cpu_count()
    pool = Pool(num_processes)

    # Указанный диапазон для генерации secret_exponent
    start_range = int("0000000000000000000000000000000000000000000000020000000000000000", 16)
    end_range = int("000000000000000000000000000000000000000000000003ffffffffffffffff", 16)

    # Запуск каждого процесса с уникальным идентификатором
    pool.map(generate_key_pair, [(i, start_range, end_range) for i in range(num_processes)])

    pool.close()
    pool.join()
