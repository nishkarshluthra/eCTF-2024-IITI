import os
import hashlib
import argparse
import asyncio
import sys
# from ectf_tools.utils import run_shell
from Crypto.Cipher import AES

def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def write_file(file_path, data):
    with open(file_path, 'w') as file:
        for line in data:
            file.write(line)

def sha256hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def aes_encrypt(data, key):
    key = bytes.fromhex(key[2:])
    cipher = AES.new(key, AES.MODE_ECB)
    data = data.encode()
    data = data + b'\x00' * (16 - len(data) % 16)
    return cipher.encrypt(data).hex()

# def aes_decrypt(data, key):
#     key = bytes.fromhex(key[2:])
#     cipher = AES.new(key, AES.MODE_ECB)
#     data = bytes.fromhex(data)
#     return cipher.decrypt(data).decode()

def edit_ap(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f'File {file_path} does not exist')
    params = ['AP_PIN', 'AP_TOKEN']
    data = read_file(file_path)
    for i in range(len(data)):
        for param in params:
            if param in data[i]:
                words = data[i].split(' ')
                index = words.index(param)
                words[index+1] = words[index+1].replace('\n', '')
                words[index+1] = words[index+1][1:-1]
                words[index+1] = f'"{sha256hash(words[index+1])}"'
                data[i] = ' '.join(words)
                data[i] += '\n'
    write_file(file_path, data)
    # asyncio.run(run_shell(f'python3 ../Utils/write_file.py {file_path} {data}'))
    # print(data)

def edit_component(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f'File {file_path} does not exist')
    data = read_file(file_path)
    params = ['ATTESTATION_LOC', 'ATTESTATION_DATE', 'ATTESTATION_CUSTOMER']
    global_secrets = read_file('../deployment/global_secrets.h')
    # aes_key = b'Sixteen byte key'.hex()
    for secret in global_secrets:
        if 'C_KEY' in secret:
            aes_key = secret.split(' ')[-1]
            break
    aes_key = aes_key.replace('\n', '')
    aes_key = aes_key.replace('\"', '')
    component_id = ''
    for i in range(len(data)):
        if 'COMPONENT_ID' in data[i]:
            component_id = data[i].split(' ')[-1][2:]
            break
    component_id = component_id.replace('\n', '')
    component_id = int(component_id, 16)
    # component_id = int(component_id)
    xor = component_id ^ int(aes_key, 16)
    final_key = hex(xor)
    # final_key = final_key[2:]
    for i in range(len(data)):
        for param in params:
            if param in data[i]:
                words = data[i].split(' ')
                index = words.index(param)
                new_data = words[index+1:]
                new_data = ' '.join(new_data)
                new_data = new_data.replace('\n', '')
                new_data = new_data.replace('\"', '')
                words[index+1] = f'"{aes_encrypt(new_data, final_key)}"'
                for j in range(len(words)):
                    if j > index+1:
                        words.pop()
                data[i] = ' '.join(words)
                data[i] += '\n'
    write_file(file_path, data)

    # # testing 
    # for i in range(len(data)):
    #     for param in params:
    #         if param in data[i]:
    #             words = data[i].split(' ')
    #             index = words.index(param)
    #             print("Param: " + param + "Decrypt: " + aes_decrypt(words[index+1], final_key))

def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('component', type=str, help='Component name')
    argparser.add_argument('file_path', type=str, help='File path')
    args = argparser.parse_args()

    if args.component == 'ap':
        edit_ap(args.file_path)
    elif args.component == 'component':
        edit_component(args.file_path)

if __name__ == '__main__':
    main()
# argparser = argparse.ArgumentParser()
# argparser.add_argument('component', type=str, help='Component name')
# argparser.add_argument('file_path', type=str, help='File path')
# args = argparser.parse_args()

# if args.component == 'ap':
#     edit_ap(args.file_path)
# elif args.component == 'component':
#     edit_component(args.file_path)