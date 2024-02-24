import ecdsa
import hashlib
import base58
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
import secrets

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

def generate_and_check_target(args):
    target_address, start, end = args
    for _ in range(start, end):
        # Генерация случайного числа с битовой длиной 25
        current_private_key = secrets.randbits(25)
        current_private_key, current_address = generate_key_pair(current_private_key)

        if current_address == target_address:
            print(f"Найден целевой биткоин-адрес: {target_address}")
            print(f"Приватный ключ для целевого адреса: {bin(current_private_key)[2:]}")

            with open("F13.txt", "a") as file:
                file.write(f"Целевой биткоин-адрес: {target_address}\n")
                file.write(f"Приватный ключ: {bin(current_private_key)[2:]}\n")

            return True

        print(f"Private Key: {bin(current_private_key)[2:]} | Address: {current_address}")

    return False

if __name__ == "__main__":
    target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP"
    output_file = "F13.txt"
    num_processes = cpu_count()

    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        chunk_size = 2**24
        start_values = [0]
        end_values = [1 << 25]
        args_list = [(target_address, start, end) for start, end in zip(start_values, end_values)]

        try:
            futures = [executor.submit(generate_and_check_target, args) for args in args_list]
            for future in as_completed(futures):
                if future.result():
                    print("Программа завершена.")
                    break
        except KeyboardInterrupt:
            print("Программа завершена.")
