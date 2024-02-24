print("Start Project13")

import ecdsa
from Crypto.Util.number import long_to_bytes
import base58
import secrets
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

def generate_key_pair(private_key):
    curve = ecdsa.SECP256k1
    base_point = curve.generator
    base_private_key_point = base_point * private_key

    base_public_key_bytes = ecdsa.VerifyingKey.from_public_point(base_private_key_point, curve).to_string("compressed")
    sha256_hash = ecdsa.util.sha256(base_public_key_bytes).digest()
    ripemd160_hash = long_to_bytes(int.from_bytes(sha256_hash, 'big'), 20)
    network_byte = b"\x00"
    checksum = ecdsa.util.double_sha256(network_byte + ripemd160_hash).digest()[:4]
    address = base58.b58encode(network_byte + ripemd160_hash + checksum).decode("utf-8")

    return private_key, address

def generate_and_check_target(args):
    target_address, stop_flag, output_file = args
    try:
        while not stop_flag.is_set():
            # Generate a random 25-bit number in the range (2^24) to (2^25 - 1)
            private_key = secrets.randbelow(1 << 25)
            current_private_key, current_address = generate_key_pair(private_key)

            if current_address == target_address:
                print(f"Найден целевой биткоин-адрес: {target_address}")
                print(f"Приватный ключ для целевого адреса: {format(current_private_key, 'x')}")
                stop_flag.set()

                # Запись в файл
                with open(output_file, "a") as file:
                    file.write(f"Целевой биткоин-адрес: {target_address}\n")
                    file.write(f"Приватный ключ: {format(current_private_key, 'x')}\n")

                break

    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP"
    output_file = "F13.txt"

    num_cpus = multiprocessing.cpu_count()
    stop_flag = multiprocessing.Event()
    args = [(target_address, stop_flag, output_file) for _ in range(num_cpus)]

    with ProcessPoolExecutor(max_workers=num_cpus) as process_executor:
        futures = [process_executor.submit(generate_and_check_target, arg) for arg in args]

        for completed_future in as_completed(futures):
            try:
                completed_future.result()
            except Exception as e:
                print(f"An error occurred: {e}")

    print("Программа завершена.")
