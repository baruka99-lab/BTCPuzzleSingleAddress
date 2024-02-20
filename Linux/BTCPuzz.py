print("Start! Good Luck!")

import fastecdsa
from fastecdsa import ecdsa, keys
import hashlib
import base58
from multiprocessing import Pool, cpu_count
import random
import os

def generate_key_pair(args):
    process_id, start_range, end_range = args
    random_generator = random.SystemRandom()
    
    while True:
        # Генерация случайного числа в указанном диапазоне
        secret_exponent = int.from_bytes(os.urandom(32), byteorder='big') % (end_range - start_range) + start_range

        # Преобразование случайного числа в закрытый ключ
        private_key = fastecdsa.keys.gen_private_key(fastecdsa.curve.secp256k1, secret_exponent)

        # Получение сжатого открытого ключа
        compressed_public_key = ecdsa.get_public_key(private_key)

        # Хэширование открытого ключа для получения отпечатка с использованием SHA-256
        sha256_hash = hashlib.sha256(compressed_public_key.to_bytes()).digest()

        # Хэширование SHA-256 для получения отпечатка с использованием RIPEMD-160
        ripemd160_hash = hashlib.new('ripemd160')
        ripemd160_hash.update(sha256_hash)
        ripemd160_hash = ripemd160_hash.digest()

        # Добавление префикса к хэшу (для Bitcoin-адреса)
        prefixed_public_key_hash = b'\x00' + ripemd160_hash  # 0x00 для основной сети

        # Вычисление контрольной суммы
        checksum = hashlib.sha256(hashlib.sha256(prefixed_public_key_hash).digest()).digest()[:4]

        # Формирование Bitcoin-адреса в кодировке base58
        bitcoin_address = base58.b58encode(prefixed_public_key_hash + checksum).decode('utf-8')

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
            found_file.write(f"Закрытый ключ: {private_key.to_bytes().hex()}\n")
        print("Целевой адрес найден!")
        print(f"Процесс {process_id}: Закрытый ключ: {private_key.to_bytes().hex()}")
        print(f"Процесс {process_id}: Сжатый открытый ключ: {compressed_public_key.to_bytes().hex()}")
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
