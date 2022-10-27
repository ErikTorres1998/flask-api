import requests
import json
# first create username before calling this api
url = "https://flask-team32-api.herokuapp.com/api_login"

payload = json.dumps({
  "username": "ErikTorres",
  "password": "1235577",
  "email": "eriktorres1DB@mail.com"
})
headers = {
  'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
