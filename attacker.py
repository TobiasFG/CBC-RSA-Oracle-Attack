# Import request library
import requests

# url of local server to attack
URL = 'http://127.0.0.1:5000'
URL_QUOTE = 'http://127.0.0.1:5000/quote'

# get a cookie from the server with the authtoken

session = requests.Session() # create a session
session.get(URL) # get the url
cookie = session.cookies.get_dict() # get the cookie

authtoken = cookie['authtoken'] # The authtoken
authtoken_bytes = bytes.fromhex(authtoken) # authtoken as bytes

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
