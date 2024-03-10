print("Start")

import hashlib
import ecdsa
from Crypto.Hash import RIPEMD160
import base58check
from multiprocessing import Pool, cpu_count
import secrets

def generate_key_pair(process_id):
    while True:
        # Генерация случайного числа в диапазоне с 2**65 до 2**66 - 1
        secret_exponent = secrets.randbelow(2**66 - 2**65) + 2*65

        # Преобразование случайного числа в приватный ключ
        private_key = ecdsa.SigningKey.from_secret_exponent(secret_exponent, curve=ecdsa.SECP256k1)

        # Получение сжатого публичного ключа
        compressed_public_key = private_key.get_verifying_key().to_string("compressed")

        # Хеширование публичного ключа для получения отпечатка
        h = RIPEMD160.new()
        h.update(hashlib.sha256(compressed_public_key).digest())
        public_key_hash = h.digest()

        # Добавление префикса к хешу (для биткоин-адреса)
        prefixed_public_key_hash = b'\x00' + public_key_hash  # 0x00 для основной сети (mainnet)

        # Вычисление контрольной суммы
        h = hashlib.sha256()
        h.update(hashlib.sha256(prefixed_public_key_hash).digest())
        checksum = h.digest()[:4]

        # Формирование биткоин-адреса в base58check
        bitcoin_address = base58check.b58encode(prefixed_public_key_hash + checksum).decode('utf-8')

        # Приватный ключ в десятичном формате
        private_key_decimal = int(private_key.to_string().hex(), 16)

        print(f"Process {process_id}: Private Key (Decimal): {private_key_decimal}")
        print(f"Process {process_id}: Compressed Public Key: {compressed_public_key.hex()}")
        print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}\n")

        # Проверка и запись в файл found.txt или address.txt
        if check_and_write_address(process_id, compressed_public_key, bitcoin_address, private_key, private_key_decimal):
            # Прерывание цикла, если найден нужный адрес
            break

def check_and_write_address(process_id, compressed_public_key, bitcoin_address, private_key, private_key_decimal):
    # Проверка наличия определенного адреса
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"  # Целевой адрес
    if bitcoin_address == target_address:
        # Запись найденного адреса в файл
        with open('F13.txt', 'a') as found_file:
            found_file.write(f"Found Target Address: {bitcoin_address}\n")
            found_file.write(f"Private Key (Hex): {private_key.to_string().hex()}\n")
            found_file.write(f"Private Key (Decimal): {private_key_decimal}\n")
        print(f"Process {process_id}: Private Key (Decimal): {private_key_decimal}")
        print(f"Process {process_id}: Compressed Public Key: {compressed_public_key.hex()}")
        print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}\n")
        return True

    return False

if __name__ == '__main__':
    num_processes = cpu_count()
    pool = Pool(num_processes)

    # Запуск каждого процесса с уникальным идентификатором
    pool.map(generate_key_pair, range(num_processes))

    pool.close()
    pool.join()
