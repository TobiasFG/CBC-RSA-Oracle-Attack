# Import request library
from audioop import reverse
import requests

# Size of the IV block
BLOCK_SIZE = 16

# url of local server to attack
URL = 'http://127.0.0.1:5000'
URL_QUOTE = 'http://127.0.0.1:5000/quote'

# get a cookie from the server with the authtoken

session = requests.Session() # create a session
session.get(URL) # get the url
cookie = session.cookies.get_dict() # get the cookie

authtoken = cookie['authtoken'] # The authtoken
authtoken_bytes = bytes.fromhex(authtoken) # authtoken as bytes

# Split the authtoken into blocks
def split_blocks(bytes):
    blocks = []
    for i in range(0, len(bytes), BLOCK_SIZE):
        blocks.append(bytes[i:i+BLOCK_SIZE])
    return blocks

authtoken_blocks = split_blocks(authtoken_bytes)

# check if padding is correct
def check_cookie(authtoken):
    cookie = {'authtoken': authtoken}
    response = requests.get(URL_QUOTE, cookies=cookie)
    if 'No quote for you!' in response.text:
        return False
    if '??' in response.text:
        return True

# see what happens when the received cookie is used directly
print(check_cookie(authtoken))

IV = [] # Initialization Vector
PAD = [] # Padding Vector

# For each byte in the block last block
block = authtoken_blocks[-1]

for byte in range(len(block)):
    for tester in range(256):
        # if block[byte] xor tester == byte then we have the correct byte
        if (block[byte] ^ tester == byte):
            # append the byte to the IV
            IV.append(tester)
            break
    # Create a Zero Initialization Vector
    ZIV = [byte] * len(IV)
    # take the auth_byte_index first bytes of the auth_token
    xorer = block[:byte]
    # xor the ZIV with the xorer
    IV = xorer ^ ZIV
