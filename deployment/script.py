import secrets
import os

def generate_key():
    key = secrets.token_hex(16)
    with open('global_secrets.h', 'w') as f:
        f.write('#define C_KEY "{}"\n'.format(key))
    return key

generate_key()