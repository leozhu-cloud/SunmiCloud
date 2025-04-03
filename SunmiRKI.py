import json
import time
import random
import hashlib
import requests

# 配置 API 相关信息
UAT_URL = "https://rki.uat.sunmi.com:28443"
PROD_URL = "https://rki-mutual.sunmi.com"

# Group ID and Token（From Sunmi）
ORG_ID = '8a09ab52-5feb-489d-863f-d5526f8745be'
TOKEN = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3xE'

# Client Certificate（Mutual TLS）
CERT_PATH = "./certs/ssl-client.pem"  # 客户端证书
KEY_PATH = "./certs/ssl-client.key"   # 客户端私钥

keyId = 'bbdfd4e0-4f97-4820-bd63-5431d007b3a8'

def generate_timestamp():
    """ Get the current timestamp (milliseconds) """
    return str(int(time.time() * 1000))


def generate_nonce():
    """ Generate a random nonce value (16-character random string) """
    return ''.join(random.choices('0123456789abcdef', k=16))


def generate_signature(request_data, token):
    """
    生成 API 请求签名
    :param request_data: API 请求参数（字典格式）
    :param token: 服务器提供的 Token
    :return: SHA-256 signature
    """
    # 1. 排序参数（按 ASCII 码）
    sorted_data = {k: request_data[k] for k in sorted(request_data)}

    # 2. 转换为 JSON 字符串（确保无空格）
    json_string = json.dumps(sorted_data, separators=(',', ':'))

    # 3. 拼接 token
    sign_string = json_string + token

    # 4. 计算 SHA-256 哈希
    signature = hashlib.sha256(sign_string.encode('utf-8')).hexdigest()
    return signature


def upload_key(url):
    """ Send Upload Key API request """
    # generate timestamp and random nonce
    timestamp = generate_timestamp()
    nonce = generate_nonce()

    # 组装 API 请求数据
    request_data = {
        "key": '63992C8255770A6B16C11CF6ECF32D87',
        "keyType": 7,
        "keyAlgType": 1,
        "keyIndex": 4,
        "keyName": "rkiApiDemo",
        "kcv": '21B7C7',
        'packageName': 'com.leotech.leotm',
        'keyLen': 16,
        'iin': 'FFFF5B',
        'orgId': ORG_ID,
        'nonce': nonce,
        'timestamp': timestamp

    }

    # generate signature
    signature = generate_signature(request_data, TOKEN)
    request_data['signature'] = signature

    # 设置请求头
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        # 发送请求（使用 Mutual TLS）
        response = requests.post(
            url+'/v2/service/uploadkey',
            json=request_data,
            headers=headers,
            cert=(CERT_PATH, KEY_PATH)  # 使用 SSL 证书
        )

        # 解析 API 响应
        response_data = response.json()
        print("Response:", json.dumps(response_data, indent=4))

        # 检查是否成功
        if response_data.get("code") == 0:
            print("✅ Key Upload Success! Key ID:", response_data["result"]["keyId"])
            return response_data["result"]["keyId"]
        else:
            print("❌ Key Upload Failed:", response_data.get("msg", "Unknown error"))

    except requests.exceptions.RequestException as e:
        print("❌ API Request Failed:", str(e))

def querying_key_injection_status(url):
    """ Send Querying Key Injection Status API request """
    # generate timestamp and random nonce
    timestamp = generate_timestamp()
    nonce = generate_nonce()


    # 组装 API 请求数据
    request_data = {
        "sn": 'P25222BW20693',
        'orgId': ORG_ID,
        'nonce': nonce,
        'timestamp': timestamp
    }

    # generate signature
    signature = generate_signature(request_data, TOKEN)
    request_data['signature'] = signature

    # 设置请求头
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        # 发送请求（使用 Mutual TLS）
        response = requests.post(
            url+'/v2/service/injectstatus',
            json=request_data,
            headers=headers,
            cert=(CERT_PATH, KEY_PATH)  # 使用 SSL Cert
        )

        # 解析 API 响应
        response_data = response.json()
        print('Response: ', json.dumps(response_data, indent=4))

        # 检查是否成功
        if response_data.get('code') == 0:
            print("✅ Querying Key Success! Result:", response_data['result'])
            print(len(response_data['result']))
            return len(response_data['result'])
        else:
            print("❌ Querying Key Failed:", response_data.get("msg", "Unknown error"))

    except requests.exceptions.RequestException as e:
        print("❌ API Request Failed:", str(e))

def unlock_device(url):
    """ Send Querying Key Injection Status API request """
    # generate timestamp and random nonce
    timestamp = generate_timestamp()
    nonce = generate_nonce()

    # 组装 API 请求数据
    request_data = {
        "sn": 'P25222BW20693',
        'orgId': ORG_ID,
        'nonce': nonce,
        'timestamp': timestamp
    }

    # generate signature
    signature = generate_signature(request_data, TOKEN)
    request_data['signature'] = signature

    # 设置请求头
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        # 发送请求（使用 Mutual TLS）
        response = requests.post(
            url + '/v2/service/unlockDevices',
            json=request_data,
            headers=headers,
            cert=(CERT_PATH, KEY_PATH)  # 使用 SSL Cert
        )

        # 解析 API 响应
        response_data = response.json()
        print('Response: ', json.dumps(response_data, indent=4))

        # 检查是否成功
        if response_data.get('code') == 0:
            print("✅ Querying Key Success! Result:", response_data['result'])
            print(len(response_data['result']))
            return len(response_data['result'])
        else:
            print("❌ Querying Key Failed:", response_data.get("msg", "Unknown error"))

    except requests.exceptions.RequestException as e:
        print("❌ API Request Failed:", str(e))


def unbind_devices(url):
    """ Send Querying Key Injection Status API request """
    # generate timestamp and random nonce
    timestamp = generate_timestamp()
    nonce = generate_nonce()

    # 组装 API 请求数据
    request_data = {
        "sn": 'P25222BW20693',
        'orgId': ORG_ID,
        'nonce': nonce,
        'timestamp': timestamp
    }

    # generate signature
    signature = generate_signature(request_data, TOKEN)
    request_data['signature'] = signature

    # 设置请求头
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        # 发送请求（使用 Mutual TLS）
        response = requests.post(
            url + '/v2/service/unbindDevices',
            json=request_data,
            headers=headers,
            cert=(CERT_PATH, KEY_PATH)  # 使用 SSL Cert
        )

        # 解析 API 响应
        response_data = response.json()
        print('Response: ', json.dumps(response_data, indent=4))

        # 检查是否成功
        if response_data.get('code') == 0:
            print("✅ Querying Key Success! Result:", response_data['result'])
            print(len(response_data['result']))
            return len(response_data['result'])
        else:
            print("❌ Querying Key Failed:", response_data.get("msg", "Unknown error"))

    except requests.exceptions.RequestException as e:
        print("❌ API Request Failed:", str(e))


if keyId == '':
    keyId = upload_key(UAT_URL)
else:
    querying_key_injection_status(UAT_URL)
    unlock_device(UAT_URL)
    unbind_devices(UAT_URL)


