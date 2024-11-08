from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import os
import time

def encrypt_file(input_file, output_file, key):
    start_encrypt = time.perf_counter_ns()
    chunk_size = 64 * 1024  # 64 KB
    init_vector = get_random_bytes(16)  # 128 bits IV for AES

    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv=init_vector)

    with open(input_file, 'rb') as in_file:
        file_size = os.path.getsize(input_file)

        # Write IV to the beginning of the output file
        with open(output_file, 'wb') as out_file:
            out_file.write(init_vector)

            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:  # Padding to make chunk size multiple of 16
                    chunk += b' ' * (16 - len(chunk) % 16)
                out_file.write(cipher.encrypt(chunk))

    print(f"{input_file} encrypted successfully.")
    end_encrypt = time.perf_counter_ns()
    return end_encrypt - start_encrypt

def decrypt_file(input_file, output_file, key):
    chunk_size = 64 * 1024  # 64 KB
    start_decrypt = time.perf_counter_ns()
    # Read IV from the beginning of the input file
    with open(input_file, 'rb') as in_file:
        init_vector = in_file.read(16)
        cipher = AES.new(key, AES.MODE_CBC, iv=init_vector)

        with open(output_file, 'wb') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                out_file.write(cipher.decrypt(chunk))

    print(f"{input_file} decrypted successfully.")
    end_decrypt = time.perf_counter_ns()
    return end_decrypt - start_decrypt

def main():
    input_folder = r"E:/ISM/project/codes/Images/"
    output_folder_encrypted = r"E:/ISM/project/codes/OutputText/"
    output_folder_decrypted = r"E:/ISM/project/codes/OutputImages/"
    prv = "super_secret_keysuper_secret_key"
    key = prv.encode('utf-8')[:32]  # Limit key to 32 bytes
    imgnames=[]
    enctimes=[]
    dectimes=[]
    # Iterate through image files in the input folder
    for filename in os.listdir(input_folder):
        if filename.endswith(".png"):
            input_file = os.path.join(input_folder, filename)
            encrypted_file = os.path.join(output_folder_encrypted, f"encrypted_{filename}.txt")
            decrypted_file = os.path.join(output_folder_decrypted, f"decrypted_{filename}")

            exec_encrypt = encrypt_file(input_file, encrypted_file, key)
            print(f"Encryption time for {filename}: {exec_encrypt} nanoseconds")
            imgnames.append(filename)
            enctimes.append(exec_encrypt)
            exec_decrypt = decrypt_file(encrypted_file, decrypted_file, key)
            print(f"Decryption time for {filename}: {exec_decrypt} nanoseconds")
            dectimes.append(exec_decrypt)
    return imgnames,enctimes,dectimes
if __name__ == "__main__":
    names,encryption_times,decryption_times=main()

data = {
    'AES File Name': names,
    'AES Encryption Time (nanoseconds)': encryption_times,
    'AES Decryption Time (nanoseconds)': decryption_times
}
