print("Start! Good Luck!")

import ecdsa
from Crypto.Hash import RIPEMD160
import hashlib
import base58
from multiprocessing import Pool, cpu_count
import os
from fastecdsa import keys, curve

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def generate_fastecdsa_private_key():
    return hex(keys.gen_private_key(curve.secp256k1))

def generate_key_pair(args):
    process_id, start_range, end_range, use_fastecdsa = args
    random_generator = os.urandom

    while True:
        # Генерация случайного закрытого ключа
        if use_fastecdsa:
            private_key = generate_fastecdsa_private_key()
        else:
            private_key = generate_private_key()

        # Преобразование закрытого ключа в объект ecdsa.SigningKey
        private_key = int(private_key, 16)
        private_key = ecdsa.SigningKey.from_secret_exponent(private_key, curve=ecdsa.SECP256k1)

        # Получение сжатого открытого ключа
        compressed_public_key = private_key.get_verifying_key().to_string("compressed")

        # Хэширование открытого ключа для получения отпечатка с использованием RIPEMD-160
        ripemd160_hash = RIPEMD160.new(hashlib.sha256(compressed_public_key).digest()).digest()

        # Добавление префикса к хэшу (для Bitcoin-адреса)
        prefixed_public_key_hash = b'\x00' + ripemd160_hash  # 0x00 для основной сети

        # Вычисление контрольной суммы
        checksum = hashlib.sha256(hashlib.sha256(prefixed_public_key_hash).digest()).digest()[:4]

        # Формирование Bitcoin-адреса в кодировке base58
        bitcoin_address = base58.b58encode(prefixed_public_key_hash + checksum).decode('utf-8')

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
    args = {
        'verbose': 0,
        'substring': 8,
        'fastecdsa': True,  # Установите в True для использования fastecdsa
        'cpu_count': multiprocessing.cpu_count(),
    }
    
    num_processes = args['cpu_count']
    pool = Pool(num_processes)

    # Указанный диапазон для генерации secret_exponent
    start_range = int("0000000000000000000000000000000000000000000000020000000000000000", 16)
    end_range = int("000000000000000000000000000000000000000000000003ffffffffffffffff", 16)

    # Запуск каждого процесса с уникальным идентификатором
    pool.map(generate_key_pair, [(i, start_range, end_range, args['fastecdsa']) for i in range(num_processes)])

    pool.close()
    pool.join()
