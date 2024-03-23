import secp256k1 as ice

def generate_bitcoin_private_key():
    # Генерируем случайное число, которое будет приватным ключом
    private_key = ice.random_scalar()
    
    # Преобразуем приватный ключ в формат WIF (Wallet Import Format)
    wif_private_key = ice.btc_pvk_to_wif(private_key)
    
    # Получаем адрес кошелька на основе приватного ключа
    bitcoin_address = ice.privatekey_to_coinaddress(ice.COIN_BTC, 0, True, private_key)
    
    return wif_private_key, bitcoin_address

# Пример использования:
for _ in range(10):  # Генерируем 10 приватных ключей и соответствующих адресов
    private_key, address = generate_bitcoin_private_key()
    print("Private Key:", private_key)
    print("Bitcoin Address:", address)
    print()
