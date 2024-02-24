from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, SECP256k1
import hashlib
from multiprocessing import Pool, cpu_count

def generate_custom_address_parallel(args):
    target_address, process_id = args
    count = 0

    while True:
        count += 1
        private_key_bytes = get_random_bytes(9)
        private_key = int.from_bytes(private_key_bytes, 'big')

        if private_key.bit_length() > 66:
            private_key >>= (private_key.bit_length() - 66)

        private_key_obj = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
        public_key = private_key_obj.get_verifying_key().to_string()
        address_compressed = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).hexdigest()

        print("Процесс {}: Итерация {}: Генерация приватного ключа: {}".format(process_id, count, private_key_obj.to_string().hex()))

        if address_compressed == target_address:
            print("\nПроцесс {}: Совпадение найдено после {} итераций.".format(process_id, count))
            print("Пользовательский Bitcoin-адрес:", address_compressed)
            print("Приватный ключ:", private_key_obj.to_string().hex())

            # Запись в файл found13.txt
            with open('found13.txt', 'w') as file:
                file.write("Bitcoin Address: {}\n".format(address_compressed))
                file.write("Private Key: {}\n".format(private_key_obj.to_string().hex()))

            print("Информация записана в файл found13.txt.")
            return address_compressed, private_key_obj.to_string().hex()

if __name__ == "__main__":
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    processes = cpu_count()  # Получаем количество ядер CPU
    pool = Pool(processes=processes)
    args_list = [(target_address, i) for i in range(processes)]

    results = pool.map(generate_custom_address_parallel, args_list)
    pool.close()
    pool.join()

    for result in results:
        if result:
            break
