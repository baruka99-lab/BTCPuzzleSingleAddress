print("Start Project13")

import ecdsa
from Crypto.Hash import new as hashlib
import base58
import secrets
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import cpu_count

def generate_key_pair(private_key):
    curve = ecdsa.SECP256k1
    base_point = curve.generator
    base_private_key_point = base_point * private_key

    base_public_key_bytes = ecdsa.VerifyingKey.from_public_point(base_private_key_point, curve).to_string("compressed")
    sha256_hash = hashlib("sha256")
    sha256_hash.update(base_public_key_bytes)
    ripemd160_hash = hashlib("ripemd160")
    ripemd160_hash.update(sha256_hash.digest())
    network_byte = b"\x00"
    checksum = hashlib("sha256")
    checksum.update(hashlib("sha256").update(network_byte + ripemd160_hash.digest()).digest())
    checksum = checksum.digest()[:4]

    address = base58.b58encode(network_byte + ripemd160_hash.digest() + checksum).decode("utf-8")

    return private_key, address

def generate_and_check_target(target_address, output_file):
    try:
        while True:
            # Generate a random 66-bit number in the range (2^65) to (2^66 - 1)
            private_key = secrets.randbelow(1 << 66 - 1) + (1 << 65)
            current_private_key, current_address = generate_key_pair(private_key)

            print(f"Iсходный приватный ключ: {hex(current_private_key)[2:]}")
            print(f"Iсходный биткоин-адрес: {current_address}\n")

            if current_address == target_address:
                print(f"Найден целевой биткоин-адрес: {target_address}")
                print(f"Приватный ключ для целевого адреса: {hex(current_private_key)[2:]}")

                # Запись в файл
                with open(output_file, "a") as file:
                    file.write(f"Целевой биткоин-адрес: {target_address}\n")
                    file.write(f"Приватный ключ: {hex(current_private_key)[2:]}\n")

                break

    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    output_file = "F13.txt"

    with ProcessPoolExecutor(max_workers=cpu_count()) as process_executor:
        futures = [process_executor.submit(generate_and_check_target, target_address, output_file) for _ in range(cpu_count())]

        for future in futures:
            future.result()

    print("Программа завершена.")
