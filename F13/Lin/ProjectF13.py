import os
import hashlib
import binascii
from concurrent.futures import ProcessPoolExecutor, as_completed
from fastecdsa import keys, curve

# Укажите свои адреса вместо предполагаемых значений
CUSTOM_ADDRESSES = {"13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"}

def generate_private_key():
    """Generate a random 66-bit hex integer which serves as a randomly generated Bitcoin private key."""
    lower_limit = 2**65
    upper_limit = (2**66 - 2**65) - 1
    random_value = int.from_bytes(os.urandom(8), byteorder='big')
    
    # Проверка на деление на ноль
    if (upper_limit - lower_limit + 1) == 0:
        return None
    
    private_key = hex(random_value % (upper_limit - lower_limit + 1) + lower_limit)[2:]
    return private_key.upper()

def private_key_to_public_key(private_key):
    """Convert hex private key to its respective compressed public key."""
    c = int('0x%s' % private_key, 0)
    d = keys.get_public_key(c, curve.secp256k1)
    return '02%s' % ('{0:x}'.format(int(d.x)))

def public_key_to_address(public_key):
    """Convert compressed public key to its respective P2PKH wallet address."""
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    try:
        var.update(hashlib.sha256(binascii.unhexlify(public_key.encode())).digest())
        var = '00' + var.hexdigest() + hashlib.sha256(
            hashlib.sha256(binascii.unhexlify(('00' + var.hexdigest()).encode())).digest()).hexdigest()[0:8]
        count = [char != '0' for char in var].index(True) // 2
        n = int(var, 16)
        while n > 0:
            n, remainder = divmod(n, 58)
            output.append(alphabet[remainder])
        for i in range(count): output.append(alphabet[0])
        return ''.join(output[::-1])
    except:
        return -1

def process(private_key, public_key, address, custom_addresses):
    """Check if the address is in the custom addresses list."""
    if address in custom_addresses:
        print(f'\nGenerated Bitcoin Address: {address}')
        print(f'Corresponding Private Key: {private_key}')
        print('This address is in the custom addresses list!\n')

def generate_and_process_keys(custom_addresses, total_keys):
    for _ in range(total_keys):
        private_key = generate_private_key()  # 66 bits
        if private_key is not None:
            public_key = private_key_to_public_key(private_key)
            address = public_key_to_address(public_key)
            if address != -1:
                process(private_key, public_key, address, custom_addresses)

if __name__ == '__main__':
    custom_addresses = set(CUSTOM_ADDRESSES)
    total_keys = 1000000  # Установите количество ключей по вашему выбору
    processes = os.cpu_count()

    with ProcessPoolExecutor(max_workers=processes) as executor:
        futures = [executor.submit(generate_and_process_keys, custom_addresses, total_keys // processes) for _ in range(processes)]

        for future in as_completed(futures):
            future.result()
