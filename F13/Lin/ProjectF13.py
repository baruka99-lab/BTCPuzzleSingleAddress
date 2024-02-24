import hashlib
import base58
from concurrent.futures import ProcessPoolExecutor, as_completed, ThreadPoolExecutor
from multiprocessing import cpu_count
from fastecdsa import keys, curve
import threading

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

    return base_private_key_point, address

def generate_and_check_target(private_key_range, target_address, output_file, lock):
    for private_key in private_key_range:
        current_private_key, current_address = generate_key_pair(private_key, curve=curve.secp256k1)
        current_private_key_point = keys.get_public_key(current_private_key, curve=curve.secp256k1)
        current_address = keys.get_address(current_private_key_point, curve=curve.secp256k1)

        if current_address == target_address:
            with lock:
                with open(output_file, "a") as file:
                    file.write(f"Целевой биткоин-адрес: {target_address}\n")
                    file.write(f"Приватный ключ: {hex(current_private_key)[2:]}\n")
            return

if __name__ == "__main__":
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    output_file = "F13.txt"
    num_workers = cpu_count()

    # Устанавливаем новый диапазон
    start = (1 << 65) + 1
    end = (1 << 66)

    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        chunk_size = (end - start) // num_workers
        futures = []

        for i in range(num_workers):
            chunk_start = start + i * chunk_size
            chunk_end = start + (i + 1) * chunk_size if i != num_workers - 1 else end
            future = executor.submit(generate_and_check_target, range(chunk_start, chunk_end), target_address, output_file, lock)
            futures.append(future)

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Произошла ошибка: {e}")

    print("Программа завершена.")
