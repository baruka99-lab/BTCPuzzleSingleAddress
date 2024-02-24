print("Start Project13")

import ecdsa
import hashlib
import base58
import secrets
from concurrent.futures import ProcessPoolExecutor
from bitcoin.wallet import CBitcoinSecret

def generate_key_pair(private_key):
    curve = ecdsa.SECP256k1
    base_point = curve.generator
    base_private_key_point = base_point * private_key

    base_public_key_bytes = ecdsa.VerifyingKey.from_public_point(base_private_key_point, curve).to_string("compressed")
    sha256_hash = hashlib.sha256(base_public_key_bytes).digest()

    # Use python-bitcoinlib for ripemd160
    ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()

    secret = CBitcoinSecret.from_secret_bytes(ripemd160_hash)
    address = secret.address()

    return private_key, address

def generate_and_check_target(target_address):
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

                return True

    except KeyboardInterrupt:
        return False

if __name__ == "__main__":
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    output_file = "F13.txt"

    with ProcessPoolExecutor() as process_executor:
        futures = [process_executor.submit(generate_and_check_target, target_address) for _ in range(process_executor._max_workers)]

        for future in futures:
            if future.result():
                # Target found, exit the loop
                break

    print("Программа завершена.")
