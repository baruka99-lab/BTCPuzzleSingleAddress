from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, SECP256k1
from bitcoinaddress import Wallet
from multiprocessing import Pool, cpu_count

def generate_custom_address_parallel(args):
    target_address, process_id = args
    count = 0

    while True:
        count += 1
        private_key_bytes = get_random_bytes(32)
        private_key_obj = SigningKey.from_secret_exponent(int.from_bytes(private_key_bytes, 'big'), curve=SECP256k1)
        
        # Генерируем биткоин-адрес
        bitcoin_address = Wallet(private_key_obj.to_string().hex()).to_address()

        print("Процесс {}: Итерация {}: Генерация приватного ключа: {}".format(process_id, count, private_key_obj.to_string().hex()))
        print("Процесс {}: Биткоин-адрес: {}".format(process_id, bitcoin_address))

        if bitcoin_address == target_address:
            print("\nПроцесс {}: Совпадение найдено после {} итераций.".format(process_id, count))
            print("Пользовательский Биткоин-адрес:", bitcoin_address)
            print("Приватный ключ:", private_key_obj.to_string().hex())

            # Запись в файл found13.txt
            with open('found13.txt', 'w') as file:
                file.write("Bitcoin Address: {}\n".format(bitcoin_address))
                file.write("Private Key: {}\n".format(private_key_obj.to_string().hex()))

            print("Информация записана в файл found13.txt.")
            return bitcoin_address, private_key_obj.to_string().hex()

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
