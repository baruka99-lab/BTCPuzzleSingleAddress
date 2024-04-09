print(".........................................................................................................")

import hashlib
import fastecdsa
from fastecdsa import keys
import random
import multiprocessing

def binary_to_hex(bin_string):
    return hex(int(bin_string, 2))[2:].zfill(len(bin_string) // 4)

def worker(num_zeros, num_ones, stop_event):

    target_hash = "20d45a6a762535700ce9e0b216e31994335db8a5"

    while True:
        if stop_event.is_set():
            break

        bits = ['0'] * num_zeros + ['1'] * (num_ones - 1)
        random.shuffle(bits)

        bits.insert(0, '1')
        private_key_bin = ''.join(bits)

        private_key_bin = '0' * (256 - 66) + private_key_bin
        private_key_hex = binary_to_hex(private_key_bin)

        sk = keys.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=fastecdsa.curve.secp256k1)
        public_key = keys.get_public_key(sk)

        compressed_public_key = '02' + public_key[0] if public_key[1] % 2 == 0 else '03' + public_key[0]
        compressed_public_key_bytes = bytes.fromhex(compressed_public_key)

        ripemd160_hash = hashlib.new('ripemd160')
        ripemd160_hash.update(hashlib.sha256(compressed_public_key_bytes).digest())
        hashed_compressed_public_key = ripemd160_hash.digest().hex()

        if hashed_compressed_public_key == target_hash:
            print(private_key_hex)
            print("hash160:", hashed_compressed_public_key)
            print("Target hash found!")

            stop_event.set()
            break

def main():
    num_processes = multiprocessing.cpu_count()
    processes = []
    stop_event = multiprocessing.Event()

    for _ in range(num_processes):
        process = multiprocessing.Process(target=worker, args=(31, 35, stop_event))
        processes.append(process)

    for process in processes:
        process.start()

    for process in processes:
        process.join()

    if stop_event.is_set():
        for process in processes:
            process.terminate()

if __name__ == '__main__':
    main()
