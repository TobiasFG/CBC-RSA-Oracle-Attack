# Import request library
import requests

# url of local server to attack
URL = 'http://127.0.0.1:5000'

# get a cookie from the server with the authtoken

session = requests.Session() # create a session
session.get(URL) # get the url
cookie = session.cookies.get_dict() # get the cookie

authtoken = cookie['authtoken'] # The authtoken
authtoken_bytes = bytes.fromhex(authtoken) # authtoken as bytes
