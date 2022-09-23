# Import request library
import requests as requests

# Size of the IV block
BLOCK_SIZE = 16

# url of local server to attack
URL = 'http://127.0.0.1:5000'
URL_QUOTE = 'http://127.0.0.1:5000/quote'

# get a cookie from the server with the authtoken
def get_authtoken():
    session = requests.Session() # create a session
    session.get(URL) # get the url
    cookie = session.cookies.get_dict() # get the cookie

    authtoken = cookie['authtoken'] # The authtoken
    return bytes.fromhex(authtoken) # authtoken as bytes

# Split the bytes into blocks
def split_blocks(bytes):
    return [bytes[i:i + BLOCK_SIZE] for i in range(0, len(bytes), BLOCK_SIZE)]

# check if padding is correct
def check_cookie(authtoken):
    cookie = {'authtoken': authtoken}
    response = requests.get(URL_QUOTE, cookies=cookie)
    if 'No quote for you!' in response.text:
        return False
    if '??' in response.text:
        return True

authtoken = get_authtoken() # get an authtoken
blocks = split_blocks(authtoken) # split the authtoken into blocks

for block_index in reversed(range(len(blocks))): # iterate over the blocks in reverse order
    block = blocks[block_index] # get the block
    for byte in reversed(range(len(blocks[block_index]))): # iterate over the bytes in reverse order
        for test_byte in range(256): # iterate over all possible bytes
            
            blocks[block_index][byte] = test_byte # replace the byte with the test byte
            if check_cookie(blocks): # check if the padding is correct
                print('Found byte: ' + test_byte) # print the byte
                break # break the loop


print(blocks)


            
            



            


