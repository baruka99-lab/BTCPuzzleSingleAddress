import binascii
import hashlib
import base58
import random
from Crypto.Hash import RIPEMD160
from multiprocessing import Pool, cpu_count
import ecdsa
from fastecdsa import keys, curve

def generate_private_key():
    return binascii.hexlify(random.SystemRandom().getrandbits(8*32).to_bytes(32, 'big')).decode('utf-8').upper()

def generate_fastecdsa_private_key():
    return hex(keys.gen_private_key(curve.secp256k1))

def generate_fixed_length_private_key(start_range, end_range):
    while True:
        # Генерация случайного приватного ключа в заданном диапазоне
        private_key_int = random.randint(start_range, end_range)

        # Преобразование в шестнадцатеричную строку фиксированной длины
        private_key_hex = format(private_key_int, '064x')

        # Проверка, что сгенерированный ключ входит в указанный диапазон
        if start_range <= private_key_int <= end_range:
            return private_key_hex

def generate_key_pair(args):
    process_id, start_range, end_range, use_fastecdsa = args

    while True:
        # Генерация случайного закрытого ключа
        if use_fastecdsa:
            private_key = generate_fastecdsa_private_key()
        else:
            private_key = generate_fixed_length_private_key(start_range, end_range)

        # Преобразование шестнадцатеричного представления в целое число
        private_key_int = int(private_key, 16)

        # Преобразование закрытого ключа в объект ecdsa.SigningKey
        private_key = ecdsa.SigningKey.from_secret_exponent(private_key_int, curve=ecdsa.SECP256k1)

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
        
        print(f"Process {process_id}: Private Key: {private_key.to_string().hex()}")
        print(f"Process {process_id}: Compressed Public Key: {compressed_public_key.hex()}")
        print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}\n")

        # Проверка и запись в файл found.txt или address.txt
        if check_and_write_address(bitcoin_address, private_key, compressed_public_key, process_id):
            # Прерывание цикла, если найден целевой адрес
            break

def check_and_write_address(bitcoin_address, private_key, compressed_public_key, process_id):
    # Проверка на наличие конкретного адреса
    target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP"  # Целевой адрес
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
        'cpu_count': cpu_count(),
    }

    num_processes = args['cpu_count']
    pool = Pool(num_processes)

    # Указанный диапазон для генерации secret_exponent
    start_range = int("0000000000000000000000000000000000000000000000000000000001000000", 16)
    end_range = int("0000000000000000000000000000000000000000000000000000000001ffffff", 16)

    # Запуск каждого процесса с уникальным идентификатором
    pool.map(generate_key_pair, [(i, start_range, end_range, args['fastecdsa']) for i in range(num_processes)])

    pool.close()
    pool.join()
