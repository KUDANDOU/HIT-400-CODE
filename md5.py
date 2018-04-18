# import hashlib
import requests

# filename =  "C:\Users\Funani Ndou\Downloads\Programs\heroku-cli-x64.exe"
# hasher = hashlib.md5()
# with open(filename,'rb') as open_file:
#     content = open_file.read()
#     hasher.update(content)
# print(hasher.hexdigest())

# API Key for virus total
# d0e472de35e2898540a7c66c9b60369bf7df82818ca746f38fb798afe89d0806


params = {'apikey': 'd0e472de35e2898540a7c66c9b60369bf7df82818ca746f38fb798afe89d0806'}
files = {'file': ('heroku-cli-x64.exe', open('heroku-cli-x64.exe', 'rb'))}
response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
json_response = response.json()

print(json_response)