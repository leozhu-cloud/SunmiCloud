import requests
import json
import hmac
import hashlib
import time
import random

timestamp = int(time.time())
random_number = random.randint(100000, 999999)

tmsAppId = "1538ba36-7da6-467f-aed0-51e2cabc509c"
tmsAppKey = "460c91413612153aa66d2d0333eb1c76"
tmsUrlDownload = "https://tms-api.sunmi.com/openapi/v1/params/download"

tmsUrlUpload = "https://tms-api.sunmi.com/openapi/v1/params/upload"

def test_open_api_auth(timestamp, randomNum, url, appId, appKey):
    data = {
        "package_name": "com.example.sunmiservice",
        "sn": "PC09P39610058",
        "version_code": 1
    }
    data_json = json.dumps(data)


    # Create the signature
    message = data_json + appId + str(timestamp) + str(randomNum)
    signature = hmac.new(appKey.encode(), message.encode(), hashlib.sha256).hexdigest()

    # Set headers
    headers = {
        "SunmiTms-Timestamp": str(timestamp),
        "SunmiTms-Appid": appId,
        "SunmiTms-Sign": signature,
        "SunmiTms-Nonce": str(randomNum),
        "Content-Type": "application/json"
    }

    # Send the request
    response = requests.post(url, headers=headers, data=data_json)

    # Print response
    print("Status Code:", response.status_code)
    # print("Response Body:", response.json())
    datas = response.json()['data']
    return datas
    keys_list = datas.keys()
    for key in keys_list:
        print(key, datas[key])


# 'global_params'


def test_open_api_auth_upload(timestamp, randomNum, url, appId, appKey):
    data = {
        "package_name": "com.example.sunmiservice",
        "sn": "PC09P39610058",
        "version_code": 1
    }
    data_json = json.dumps(data)


    # Create the signature
    message = data_json + appId + str(timestamp) + str(randomNum)
    signature = hmac.new(appKey.encode(), message.encode(), hashlib.sha256).hexdigest()

    # Set headers
    headers = {
        "SunmiTms-Timestamp": str(timestamp),
        "SunmiTms-Appid": appId,
        "SunmiTms-Sign": signature,
        "SunmiTms-Nonce": str(randomNum),
        "Content-Type": "application/json"
    }

    # Send the request
    response = requests.post(url, headers=headers, data=data_json)

    # Print response
    print("Status Code:", response.status_code)
    # print("Response Body:", response.json())


# Run the test function
test_open_api_auth(timestamp, random_number, tmsUrlDownload, tmsAppId, tmsAppKey)
