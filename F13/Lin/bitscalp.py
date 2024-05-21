from multiprocessing import Pool, Manager, cpu_count
import os
import codecs
from ecdsa import SigningKey, SECP256k1
from hashlib import sha256, new as hashlib_new

def generate_private_key():
    return codecs.encode(os.urandom(32), 'hex').decode()

def trim_private_key(private_key_hex, bits):
    full_binary_key = bin(int(private_key_hex, 16))[2:].zfill(256)
    trimmed_binary_key = full_binary_key[-bits:].rjust(256, '0')
    trimmed_hex_key = hex(int(trimmed_binary_key, 2))[2:].zfill(64)
    trimmed_int_key = int(trimmed_hex_key, 16)
    if trimmed_int_key == 0 or trimmed_int_key >= SECP256k1.order:
        trimmed_int_key = 1
    trimmed_hex_key = hex(trimmed_int_key)[2:].zfill(64)
    return trimmed_hex_key

def private_key_to_compressed_public_key(private_key_hex):
    private_key_bytes = codecs.decode(private_key_hex, 'hex')
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key_bytes = verifying_key.to_string()
    if public_key_bytes[63] % 2 == 0:
        compressed_public_key = b'\x02' + public_key_bytes[:32]
    else:
        compressed_public_key = b'\x03' + public_key_bytes[:32]
    return compressed_public_key

def public_key_to_address(public_key_bytes):
    sha256_pubkey = sha256(public_key_bytes).digest()
    ripemd160 = hashlib_new('ripemd160')
    ripemd160.update(sha256_pubkey)
    hashed_public_key = ripemd160.digest()
    address_bytes = b'\x00' + hashed_public_key
    checksum = sha256(sha256(address_bytes).digest()).digest()[:4]
    address_bytes += checksum
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(address_bytes, 'big')
    base58_string = ''
    while num > 0:
        num, mod = divmod(num, 58)
        base58_string = alphabet[mod] + base58_string
    for byte in address_bytes:
        if byte == 0:
            base58_string = '1' + base58_string
        else:
            break
    return base58_string

def worker(target_address, result_dict, done_flag, initial_bits):
    bits = initial_bits
    while not done_flag.is_set():
        base_private_key = generate_private_key()
        trimmed_key = trim_private_key(base_private_key, bits)
        compressed_public_key = private_key_to_compressed_public_key(trimmed_key)
        bitcoin_address = public_key_to_address(compressed_public_key)
        if bitcoin_address == target_address:
            result_dict['private_key'] = trimmed_key
            result_dict['bitcoin_address'] = bitcoin_address
            done_flag.set()
            break
        bits += 1
        if bits > 256:
            bits = 1

def main():
    target_address = "1LeBZP5QCwwgXRtmVUvTVrraqPUokyLHqe"  # Замените на целевой адрес

    manager = Manager()
    result_dict = manager.dict()
    done_flag = manager.Event()

    num_workers = cpu_count()
    pool = Pool(num_workers)

    pool.starmap_async(worker, [(target_address, result_dict, done_flag, i) for i in range(num_workers)])

    pool.close()
    pool.join()

    if 'private_key' in result_dict and 'bitcoin_address' in result_dict:
        private_key = result_dict['private_key']
        bitcoin_address = result_dict['bitcoin_address']
        print("Target Address Found!")
        print(f"Private Key: {private_key}")
        print(f"Bitcoin Address: {bitcoin_address}")
        with open('found.txt', 'w') as f:
            f.write("Target Address Found!\n")
            f.write(f"Private Key: {private_key}\n")
            f.write(f"Bitcoin Address: {bitcoin_address}\n")
    else:
        print("Target Address Not Found.")

if __name__ == "__main__":
    main()
