#!/usr/bin/python3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import binascii
from decimal import *
import argparse
import xml.etree.ElementTree as ET
from base64 import b64decode
import colorama
colorama.init()

#TO-DO consume letmost 0s from dump when doing checks, cause hex 010001 is equivalent to 10001 but check would fail
#   TO-DO add a 0 before Q in dump and test the padding management

LOG_LEVELS = ['debug', 'info', 'warn', 'error']
DEBUG_TAG = f"{colorama.Style.BRIGHT}{colorama.Fore.BLUE}[DEBUG]{colorama.Style.RESET_ALL}\t"
INFO_TAG = f"[INFO]\t"
WARN_TAG = f"{colorama.Style.BRIGHT}{colorama.Fore.YELLOW}[WARN]{colorama.Style.RESET_ALL}\t"
ERROR_TAG = f"{colorama.Style.BRIGHT}{colorama.Fore.RED}[ERROR]{colorama.Style.RESET_ALL}\t"
KEYS_FOUND = []

#   Instantiate the parser
parser = argparse.ArgumentParser(description='Optional app description')

#   Args
parser.add_argument('-f', '--file', type=str, required=True, help='Dump file to look for the key inside.')
parser.add_argument('-o', '--output', type=str, required=True, help='File to export the private RSA key to')
parser.add_argument('-e', '--exp', type=str, required=False, help='Public exponent as hex stream')
parser.add_argument('-d', '--debug-level', type=str, required=False, default='warn', choices=LOG_LEVELS)

arg_mod_input_group = parser.add_mutually_exclusive_group(required=True)
arg_mod_input_group.add_argument('-m', '--mod', type=str, required=False, help='Modulus as hex stream')
arg_mod_input_group.add_argument('-M', '--mod-file', type=str, required=False, help='File containing the modulus as hex stream')
arg_mod_input_group.add_argument('-p', '--pubkey-pem', type=str, required=False, help='File containing the public key in PEM format')
arg_mod_input_group.add_argument('-P', '--pubkey-xml', type=str, required=False, help='File containing the public key in XML format')

args = parser.parse_args()
FILE_INPUT = args.file
FILE_OUTPUT = args.output


def export_priv_pem(exp, mod, p, q, file_out):
    phi = (p - 1) * (q - 1)
    d = pow(exp, -1, phi)
    private_key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=rsa.RSAPublicNumbers(e=exp, n=mod)
    ).private_key()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    if pem not in KEYS_FOUND:
        with open(file_out, 'wb') as key_file:
            key_file.write(pem)
        KEYS_FOUND.append(pem)
    else:
        LOG_LEVELS.index(args.debug_level) <= LOG_LEVELS.index('debug') and print(DEBUG_TAG+'Duplicate key')

def read_pem_public_key(file_path):
    with open(file_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    # Extract modulus and public exponent
    modulus = public_key.public_numbers().n
    public_exponent = public_key.public_numbers().e
    return hex(modulus)[2:], public_exponent

def read_pem_public_key(file_path):
    with open(file_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    # Extract modulus and public exponent
    modulus = public_key.public_numbers().n
    public_exponent = public_key.public_numbers().e
    return hex(modulus)[2:], public_exponent

def read_xml_public_key(xml_key_file):
    with open(xml_key_file, 'r') as key_file:
        xml_key = key_file.read()
    root = ET.fromstring(xml_key)
    modulus = root.find('Modulus').text
    public_exponent = root.find('Exponent').text
    return b64decode(modulus).hex(), int.from_bytes(b64decode(public_exponent))

def create_file_name(file_name, index):
    if '.' in file_name:
        # Split the file name into name and extension
        name, extension = file_name.rsplit('.', 1)
        # Add the number before the extension
        file_name_output = f'{name}_{index}.{extension}'
    else:
        # Add the number at the end of the file name
        file_name_output = f'{file_name}_{index}.pem'
    return file_name_output

if __name__ == "__main__":
    #   Argument parsing to retrieve mod_hex, mod_value and exp_value
    if args.mod is not None:
        mod_hex = args.mod
        if args.exp is None:
            print(ERROR_TAG+'-e/--exp must be provided when -m/--mod is provided!')
            exit(1)
        exp_value = int(args.exp, 16)
    elif args.mod_file is not None:
        with open(args.mod_file, "r") as file:
            mod_hex = file.read()
    elif args.pubkey_pem is not None:
        mod_hex, exp_value = read_pem_public_key(args.pubkey_pem)
    elif args.pubkey_xml is not None:
        mod_hex, exp_value = read_xml_public_key(args.pubkey_xml)
    else:
        print(ERROR_TAG+'Should\'t get here since argparse group requires one of the arguments to be provided')
        print(ERROR_TAG+'Specify the modulus')
        exit(1)

    mod_value = int(mod_hex, 16)

    #   Calculate mod hex stream length and fix if needed
    mod_bytes_len = len(mod_hex) / 2
    if mod_bytes_len % 1 != 0:
        print(WARN_TAG+'The modulus hex stream provided has an odd length')
        print(WARN_TAG+'Script will try to add a "0" before it and run normally')
        mod_hex = '0' + mod_hex
        mod_bytes_len = len(mod_hex) / 2
    mod_bytes_len = int(mod_bytes_len)

    #   Load dump, both as binary data and hex stream
    with open(FILE_INPUT, "rb") as file:
        data = file.read()
    hex_stream = binascii.hexlify(data).decode("utf-8")

    last_found_offset_bytes = 0

    occurrences = []
    start_index = 0
    valid_keys = 1
    while True:
        index = hex_stream.find(mod_hex, start_index)
        if index == -1:
            break
        LOG_LEVELS.index(args.debug_level) <= LOG_LEVELS.index('info') and print(INFO_TAG+'Found the modulus at', hex(index // 2))
        occurrences.append(index // 2)
        start_index = index + 1

    for start_byte_offset in occurrences:
        LOG_LEVELS.index(args.debug_level) <= LOG_LEVELS.index('debug') and print(DEBUG_TAG+'Processing finding at', hex(start_byte_offset))
        end_byte_offset = start_byte_offset + mod_bytes_len
        p_bytes_len = 0
        while p_bytes_len < mod_bytes_len:
            p_bytes_len += 1
            #print('Trying to create p from hex values: ', binascii.hexlify(data[end_byte_offset : end_byte_offset + p_bytes_len]).decode("utf-8"))
            p = int.from_bytes(data[end_byte_offset:end_byte_offset+p_bytes_len])
            #print('p: ', p)
            if p <= 0:
                continue
            tup = divmod(mod_value,p)
            if tup[1] != 0:
                #print("mod not divisible by p")
                continue
            q = tup[0]
            q_hex = hex(q)[2:]  #this just removes 0x
            LOG_LEVELS.index(args.debug_level) <= LOG_LEVELS.index('debug') and print(DEBUG_TAG+'Found Q so that mod=P*Q. Q=', q_hex)
            cur_pos = end_byte_offset + p_bytes_len
            padding = 0
            while data[cur_pos + padding] == 0:
                padding += 1
            LOG_LEVELS.index(args.debug_level) <= LOG_LEVELS.index('debug') and padding > 0 and print(DEBUG_TAG+'Found',padding,'padding bytes for Q in dump.')
            cur_pos = cur_pos + padding
            data_after_p = binascii.hexlify(data[cur_pos:cur_pos + len(q_hex)//2]).decode("utf-8")
            if q_hex != data_after_p:
                #   this q is valid but it's not found after P
                LOG_LEVELS.index(args.debug_level) <= LOG_LEVELS.index('debug') and print(DEBUG_TAG+'Q wasnt found in dump after P. Instead found:', data_after_p)
                LOG_LEVELS.index(args.debug_level) <= LOG_LEVELS.index('debug') and print(DEBUG_TAG+'byte_offset of that data is: ', hex(end_byte_offset + p_bytes_len), '-',hex(end_byte_offset + p_bytes_len + len(q_hex)//2))
                continue
            LOG_LEVELS.index(args.debug_level) <= LOG_LEVELS.index('debug') and print(DEBUG_TAG+'Found Q so that mod=P*Q, q_hex:', q_hex)
            
            file_name_output = create_file_name(str(valid_keys), FILE_OUTPUT)

            print(f'{colorama.Style.BRIGHT}{colorama.Fore.GREEN}SUCCESS!{colorama.Style.RESET_ALL}\tExporting private key to:', file_name_output)
            
            export_priv_pem(exp_value, mod_value, p, q, file_name_output)
            valid_keys += 1