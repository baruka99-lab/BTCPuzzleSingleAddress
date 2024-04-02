from fastecdsa import keys, curve
import hashlib
import binascii
import random
import multiprocessing
from multiprocessing import cpu_count

def generate_key_pair(process_id, target_address, compressed=True):
    def generate_private_key():
        return hex((random.randrange((1 << 65) - 1) + (1 << 65)))[2:].upper().zfill(64)

    def private_key_to_public_key(private_key, compressed=True):
        key = keys.get_public_key(int(private_key, 16), curve.secp256k1)
        if compressed:
            return '02' + hex(key.x)[2:].zfill(64) if key.y % 2 == 0 else '03' + hex(key.x)[2:].zfill(64)
        else:
            return '04' + (hex(key.x)[2:].zfill(64) + hex(key.y)[2:].zfill(64))

    def public_key_to_address(public_key):
        # Calculate address from public key
        h = hashlib.new('ripemd160')
        h.update(hashlib.sha256(binascii.unhexlify(public_key.encode())).digest())
        return binascii.hexlify(h.digest()).decode()

    def check_and_write_address(process_id, public_key, address, private_key, target_address):
        # Compare the generated address to the target address and write to file if it matches
        if address == target_address:
            print(f"Process {process_id}: Found matching address!")
            with open('bitcoin_addresses.txt', 'a') as f:
                f.write(f"Address: {address} | Private Key: {private_key}\n")
            return True
        return False

    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key, compressed=compressed)
        address = public_key_to_address(public_key)

        # Check and write address to file
        if check_and_write_address(process_id, public_key, address, private_key, target_address):
            break

if __name__ == '__main__':
    num_processes = cpu_count()
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"  # Целевой адрес

    processes = []
    for i in range(num_processes):
        p = multiprocessing.Process(target=generate_key_pair, args=(i, target_address))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()
