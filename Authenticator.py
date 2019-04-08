import base64
import hashlib
import hmac
import os
import struct
import time

FILE_NAME = 'secrets.txt'
ENCODING = 'utf-8'
SECRET_KEY_LEN = 16


def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000
    return h


def get_totp_token(secret):
    return str(get_hotp_token(secret, intervals_no=int(time.time()) // 30)).zfill(6)


def show_prompt():
    secrets = get_secrets()
    print('Select an option:\n')
    options = list(secrets.keys())
    options.append('Add new app')
    options.append('Exit')

    for index, option in enumerate(options):
        print('{} {}'.format(index, option))

    input_val = input('\nPress number to select ')

    try:
        selected_option = int(input_val)
    except ValueError as e:
        print('Please select from options above Error -> {}'.format(e))
        show_prompt()
        return
    if selected_option == len(options) - 2:
        add_new_secrets()
    elif selected_option == len(options) - 1:
        print('\nOkay bye!')
        return
    else:
        try:
            app_name = options[selected_option].strip()
            token = get_totp_token(secrets[app_name])
            print('\nSecrets for {} --> {}'.format(app_name, token))
            try:
                os.system('echo {} | pbcopy'.format(token))
                print('{} token copied to clipboard!'.format(app_name))
            except:
                pass
        except (IndexError, ValueError) as e:
            print('\nPlease select from options above Error -> {}'.format(e))
            show_prompt()


def get_secrets():
    f = open(FILE_NAME, mode='r', encoding=ENCODING)
    secrets = {}
    for line in f:
        if not f:
            continue
        arr = line.split(',')
        secrets[arr[0]] = arr[1].rstrip('\n')
    f.close()
    return secrets


def write_to_file(key, val):
    f = open(FILE_NAME, mode='a', encoding=ENCODING)
    f.write('{},{}\n'.format(key, val))
    f.close()


def is_secrets_exist(file_name):
    return os.path.isfile(file_name) and os.path.getsize(file_name) > 0


def add_new_secrets():
    app_name = input('Please enter App name for which you want to add secrets: ')
    secret_key = input('Please enter your 16 digit secret key: ')
    if len(secret_key) != SECRET_KEY_LEN:
        print('Please enter valid key\n')
        add_new_secrets()
        return
    try:
        get_totp_token(secret_key)
    except Exception as e:
        print('Invalid secret key {}'.format(e))
        return
    write_to_file(app_name, secret_key)
    print('\nYour secret has been save successfully!\n')
    show_prompt()


if is_secrets_exist(FILE_NAME):
    show_prompt()
else:
    add_new_secrets()
