print("Start!")

import hashlib
import base58
from Crypto.Hash import RIPEMD
import base58check
from multiprocessing import Pool, cpu_count
import secrets
from fastecdsa import keys, curve, encoding

def generate_key_pair(process_id):
    while True:
        # Генерация случайного числа в диапазоне с 2**65 до 2**66 - 1
        secret_exponent = secrets.randbelow(1 << 25 - 1) + (1 << 24)

        # Преобразование случайного числа в приватный ключ
        private_key = keys.gen_private_key(curve.secp256k1)

        # Получение публичного ключа
        public_key = keys.get_public_key(private_key, curve.secp256k1)

        # Сжатие публичного ключа вручную
        compressed_public_key = encoding.sec1.SEC1Encoder().encode_public_key(public_key, compressed=True)

        # Хеширование публичного ключа для получения отпечатка
        h = RIPEMD.new()
        h.update(hashlib.sha256(compressed_public_key).digest())
        public_key_hash = h.digest()

        # Добавление префикса к хешу (для биткоин-адреса)
        prefixed_public_key_hash = b'\x00' + public_key_hash  # 0x00 для основной сети (mainnet)

        # Вычисление контрольной суммы
        h = hashlib.sha256()
        h.update(hashlib.sha256(prefixed_public_key_hash).digest())
        checksum = h.digest()[:4]

        # Формирование биткоин-адреса в base58check
        bitcoin_address = base58.b58encode(prefixed_public_key_hash + checksum).decode('utf-8')

        # Приватный ключ в десятичном формате
        private_key_decimal = int.from_bytes(private_key, byteorder='big')

        # Запись сгенерированных адреса и приватного ключа в файл
        with open('F13.txt', 'a') as found_file:
            found_file.write(f"Bitcoin Address: {bitcoin_address}\n")
            found_file.write(f"Private Key (Hex): {private_key.hex()}\n")
            found_file.write(f"Private Key (Decimal): {private_key_decimal}\n")

        # Вывод сгенерированных адреса и приватного ключа в консоль
        print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}")
        print(f"Process {process_id}: Private Key (Decimal): {private_key_decimal}")

if __name__ == '__main__':
    num_processes = cpu_count()
    pool = Pool(num_processes)

    # Запуск каждого процесса с уникальным идентификатором
    pool.map(generate_key_pair, range(num_processes))

    pool.close()
    pool.join()
