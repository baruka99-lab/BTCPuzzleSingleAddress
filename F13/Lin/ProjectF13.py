import ecdsa
import hashlib
import base58
import secrets
from multiprocessing import Pool, cpu_count

def generate_key_pair(private_key):
    curve = ecdsa.SECP256k1
    base_point = curve.generator
    base_private_key_point = base_point * private_key

    base_public_key_bytes = ecdsa.VerifyingKey.from_public_point(base_private_key_point, curve).to_string("compressed")
    sha256_hash = hashlib.sha256(base_public_key_bytes).digest()

    ripemd160_hash = sha256_hash[:20]
    network_byte = b"\x00"
    checksum = hashlib.sha256(hashlib.sha256(network_byte + ripemd160_hash).digest()).digest()[:4]
    address = base58.b58encode(network_byte + ripemd160_hash + checksum).decode("utf-8")

    return private_key, address

def generate_and_check_target(private_key):
    target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP"
    current_private_key, current_address = generate_key_pair(private_key)

    print(f"Приватный ключ: {hex(current_private_key)[2:]}")
    print(f"Биткоин-адрес: {current_address}\n")

    if current_address == target_address:
        print(f"Найден целевой биткоин-адрес: {target_address}")
        print(f"Приватный ключ для целевого адреса: {hex(current_private_key)[2:]}")

        with open("F13.txt", "a") as file:
            file.write(f"Целевой биткоин-адрес: {target_address}\n")
            file.write(f"Приватный ключ: {hex(current_private_key)[2:]}\n")

        return True

    return False

if __name__ == "__main__":
    target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP"
    output_file = "F13.txt"
    num_processes = cpu_count()

    with Pool(num_processes) as pool:
        try:
            private_key_start = 1 << 24
            private_key_end = 1 << 66

            # Generate a pool of private keys
            private_keys = range(private_key_start, private_key_end)

            # Distribute tasks to the pool
            result = pool.map(generate_and_check_target, private_keys)

            if any(result):
                print("Программа завершена.")
        except KeyboardInterrupt:
            pool.terminate()
            pool.join()
            print("Программа завершена.")
