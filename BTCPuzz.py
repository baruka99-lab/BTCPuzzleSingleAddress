import ecdsa
import hashlib
import base58check
from multiprocessing import Pool, cpu_count
import secrets

def generate_key_pair(process_id, start_range, end_range):
    while True:
        # Генерация случайного числа в указанном диапазоне
        secret_exponent = secrets.randbelow(end_range - start_range) + start_range

        # Преобразование случайного числа в приватный ключ
        private_key = ecdsa.SigningKey.from_secret_exponent(secret_exponent, curve=ecdsa.SECP256k1)

        # Получение сжатого публичного ключа
        compressed_public_key = private_key.get_verifying_key().to_string("compressed")

        # Хеширование публичного ключа для получения отпечатка
        public_key_hash = hashlib.new('ripemd160', hashlib.sha256(compressed_public_key).digest()).digest()

        # Добавление префикса к хешу (для биткоин-адреса)
        prefixed_public_key_hash = b'\x00' + public_key_hash  # 0x00 для основной сети (mainnet)

        # Вычисление контрольной суммы
        checksum = hashlib.sha256(hashlib.sha256(prefixed_public_key_hash).digest()).digest()[:4]

        # Формирование биткоин-адреса в base58check
        bitcoin_address = base58check.b58encode(prefixed_public_key_hash + checksum).decode('utf-8')

        print(f"Process {process_id}: Private Key: {private_key.to_string().hex()}")
        print(f"Process {process_id}: Compressed Public Key: {compressed_public_key.hex()}")
        print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}\n")

        # Проверка и запись в файл found.txt или address.txt
        if check_and_write_address(bitcoin_address, private_key, process_id):
            # Прерывание цикла, если найден нужный адрес
            break

def check_and_write_address(bitcoin_address, private_key, process_id):
    # Проверка наличия определенного адреса
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"  # Целевой адрес
    if bitcoin_address == target_address:
        # Запись найденного адреса в файл
        with open('found.txt', 'a') as found_file:
            found_file.write(f"Found Target Address: {bitcoin_address}\n")
            found_file.write(f"Private Key: {private_key.to_string().hex()}\n")
        print("Target Address Found!")
        print(f"Process {process_id}: Private Key: {private_key.to_string().hex()}")
        print(f"Process {process_id}: Compressed Public Key: {compressed_public_key.hex()}")
        print(f"Process {process_id}: Bitcoin Address: {bitcoin_address}\n")
        return True

    return False

if __name__ == '__main__':
    num_processes = cpu_count()
    pool = Pool(num_processes)

    # Указанный диапазон для генерации secret_exponent
    start_range = int("0000000000000000000000000000000000000000000000020000000000000000", 16)
    end_range = int("000000000000000000000000000000000000000000000003ffffffffffffffff", 16)

    # Запуск каждого процесса с уникальным идентификатором
    pool.starmap(generate_key_pair, [(i, start_range, end_range) for i in range(num_processes)])

    pool.close()
    pool.join()
