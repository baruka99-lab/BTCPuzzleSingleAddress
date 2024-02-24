import hashlib
import base58
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
from fastecdsa import ecdsa, keys, curve

def generate_key_pair(private_key, curve=curve.secp256k1):
    base_point = curve.G
    base_private_key_point = base_point * private_key

    base_public_key = keys.get_public_key(base_private_key_point, curve=curve)
    base_public_key_bytes = base_public_key.to_bytes()

    sha256_hash = hashlib.sha256(base_public_key_bytes).digest()
    ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
    network_byte = b"\x00"
    checksum = hashlib.sha256(hashlib.sha256(network_byte + ripemd160_hash).digest()).digest()[:4]
    address = base58.b58encode(network_byte + ripemd160_hash + checksum).decode("utf-8")

    return private_key  # Возвращаем целочисленное значение приватного ключа

def generate_and_check_target(target_address, output_file, start, end):
    for private_key in range(start, end):
        # Generate the key pair and get the correct private key value
        current_private_key = generate_key_pair(private_key, curve=curve.secp256k1)
        current_private_key_point = keys.get_public_key(current_private_key, curve=curve.secp256k1)
        current_address = keys.get_address(current_private_key_point, curve=curve.secp256k1)

        print(f"Приватный ключ: {hex(current_private_key)[2:]}")
        print(f"Биткоин-адрес: {current_address}\n")

        if current_address == target_address:
            print(f"Найден целевой биткоин-адрес: {target_address}")
            print(f"Приватный ключ для целевого адреса: {hex(current_private_key)[2:]}")

            with open(output_file, "a") as file:
                file.write(f"Целевой биткоин-адрес: {target_address}\n")
                file.write(f"Приватный ключ: {hex(current_private_key)[2:]}\n")

            return

if __name__ == "__main__":
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    output_file = "F13.txt"
    num_processes = cpu_count()

    # Устанавливаем новый диапазон
    start = (1 << 65) + 1
    end = (1 << 66)

    with ProcessPoolExecutor(max_workers=num_processes) as process_executor:
        futures = []

        # Разбиваем диапазон приватных ключей между процессами
        chunk_size = (end - start) // num_processes
        for i in range(num_processes):
            chunk_start = start + i * chunk_size
            chunk_end = start + (i + 1) * chunk_size if i != num_processes - 1 else end
            futures.append(process_executor.submit(generate_and_check_target, target_address, output_file, chunk_start, chunk_end))

        # Ждем завершения всех процессов
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Произошла ошибка: {e}")

    print("Программа завершена.")
