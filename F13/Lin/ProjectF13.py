import hashlib
import base58
import ecdsa
from concurrent.futures import ProcessPoolExecutor
import multiprocessing

def generate_key_pair(private_key, curve=ecdsa.SECP256k1):
    sk = ecdsa.SigningKey.from_secret_exponent(private_key, curve=curve)
    vk = sk.get_verifying_key()

    public_key_bytes = vk.to_string()
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
    network_byte = b"\x00"
    checksum = hashlib.sha256(hashlib.sha256(network_byte + ripemd160_hash).digest()).digest()[:4]
    address = base58.b58encode(network_byte + ripemd160_hash + checksum).decode("utf-8")

    return private_key, address

def generate_and_check_target(args):
    target_address, output_file, start, end = args
    for private_key in range(start, end):
        current_private_key, current_address = generate_key_pair(private_key)

        if current_address == target_address:
            print(f"Найден целевой биткоин-адрес: {target_address}")
            print(f"Приватный ключ для целевого адреса: {hex(current_private_key)[2:]}")

            with open(output_file, "a") as file:
                file.write(f"Целевой биткоин-адрес: {target_address}\n")
                file.write(f"Приватный ключ: {hex(current_private_key)[2:]}\n")

            return

def main():
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    output_file = "F13.txt"
    num_processes = multiprocessing.cpu_count()

    # Устанавливаем новый диапазон
    start = (1 << 65) + 1
    end = (1 << 66)

    with ProcessPoolExecutor(max_workers=num_processes) as process_executor:
        args_list = [(target_address, output_file, start + i, start + i + 1) for i in range(num_processes)]
        process_executor.map(generate_and_check_target, args_list)

    print("Программа завершена.")

if __name__ == "__main__":
    main()
