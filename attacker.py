import requests as requests
from Crypto.Util.Padding import pad, unpad
import os

BLOCK_SIZE = 16

# url of local server to attack
URL = 'http://127.0.0.1:5000'
URL_QUOTE = URL + '/quote'

LIVE_URL = 'https://cbc-rsa.netsec22.dk:8000'
LIVE_URL_QUOTE = LIVE_URL + '/quote'

secret = "I should have used authenticated encryption because ..."
topSecret = secret + ' plain CBC is not secure!'


def get_authtoken():  # get a cookie from the server with the authtoken
    session = requests.Session()  # create a session
    session.get(LIVE_URL, verify=False)  # get the url
    cookie = session.cookies.get_dict()  # get the cookie
    authtoken = cookie['authtoken']  # The authtoken

    return bytearray.fromhex(authtoken)  # authtoken as bytes


def to_hex(bytearray):  # bytearray to hex string
    return bytearray.hex()


def oracle(authtoken):  # check if the authtoken has valid padding
    cookie = {'authtoken': authtoken}
    response = requests.get(LIVE_URL_QUOTE, cookies=cookie, verify=False)
    if response.text.__contains__(''''utf'''):
        return True  # valid padding
    elif response.text.__contains__('No'):
        return True  # Success
    else:
        return False  # invalid padding


def get_quote(authtoken):  # get the quote from the server
    cookie = {'authtoken': authtoken}  # create a cookie with the authtoken
    response = requests.get(LIVE_URL_QUOTE, cookies=cookie, verify=False)  # get the quote
    return response.text  # return the quote


def single_block_attack(block):
    zeroing_iv = [0] * BLOCK_SIZE
    for pad_val in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]
        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            authtoken = to_hex(iv + block)
            if oracle(authtoken):
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    authtoken = to_hex(iv + block)
                    if not oracle(authtoken):
                        continue
                break
        else:
            raise Exception(
                "no valid padding byte found (is the oracle working correctly?)")

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return zeroing_iv


def full_attack(ct):
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    result = b''
    iv = blocks[0]
    for ct in blocks[1:]:
        dec = single_block_attack(ct)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct

    return result

def reverse_bytes(bytes):
    return bytes[::-1]

def encrypt_attack():
    cipherBytes = bytearray()
    plaintext = pad(f'{topSecret}'.encode(), BLOCK_SIZE)
    plaintextBlocks = [plaintext[i:i + BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)]  # split the plaintext into blocks
    randomCipherBlock = bytearray(os.urandom(BLOCK_SIZE))  # generate a random IV
    cipherBytes.extend(reverse_bytes(randomCipherBlock))  # add the IV to the ciphertext

    for block in reversed(range(0, len(plaintextBlocks))):  # encrypt the plaintext blocks
        padding = single_block_attack(randomCipherBlock)  # get the padding
        plaintextBlock = plaintextBlocks[block]  # get the plaintext block
        for byte in reversed(range(0, BLOCK_SIZE)):
            randomCipherBlock[byte] = plaintextBlock[byte] ^ padding[byte]
            cipherBytes.extend(randomCipherBlock[byte].to_bytes(1, byteorder='big'))

    # reverse the cipherBytes
    cipherBytes = reverse_bytes(cipherBytes)
    return get_quote(cipherBytes.hex())

# authtoken = get_authtoken() # get an authtoken
#fullAttack_decoded = full_attack(authtoken)
print(encrypt_attack())
