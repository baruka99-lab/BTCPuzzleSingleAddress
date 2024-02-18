print("Start! Good Luck!")

import ecdsa
from Crypto.Hash import RIPEMD160
import hashlib
import base58
from multiprocessing import Pool, cpu_count
import random

def generate_key_pair(args):
    process_id, start_range, end_range = args
    random_generator = random.SystemRandom()
    
    while True:
        # Генерация случайного числа в указанном диапазоне
        secret_exponent = random_generator.randrange(start_range, end_range)

        # Преобразование случайного числа в закрытый ключ
        private_key = ecdsa.SigningKey.from_secret_exponent(secret_exponent, curve=ecdsa.SECP256k1)

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
    target_address = "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum"  # Целевой адрес
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
    start_range = int("0000000000000000000000000000000000000000000000000000000000080000", 16)
    end_range = int("00000000000000000000000000000000000000000000000000000000000fffff", 16)

    # Запуск каждого процесса с уникальным идентификатором
    pool.map(generate_key_pair, [(i, start_range, end_range) for i in range(num_processes)])

    pool.close()
    pool.join()
