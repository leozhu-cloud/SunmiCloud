import hashlib
import hmac
import json
import requests
import time
from typing import Any, Dict, List, Tuple
import uuid
from PIL import Image
import os

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.axml import AXMLPrinter
from asn1crypto import x509
from cryptography.hazmat.backends import default_backend


sn = []
apk_name = 'Leo Terminal Management'
# 替换为您申请的APPID&APPKEY Replace the applied APPID&APPKEY
APP_ID: str = '2ce40c7a922346e48bfa90d6bafedf3e'
APP_KEY: str = '4918e232e0594106b2b62652cd7d85c6'
timestamp = str(int(time.time()))

apk_path = '/Users/leozhu/Sunmi/SDK/apk/Leo Terminal Management-1.1-debug.apk'

# try:
#     apk = APK(apk_path)
#
#     # 获取APK信息
#     app_name = apk.get_app_name()
#     package_name = apk.get_package()
#     version_name = apk.get_androidversion_name()
#     version_code = apk.get_androidversion_code()
#     certificates = apk.get_certificates()
#     # 获取AndroidManifest.xml文件的二进制数据
#     xml_data = apk.get_android_manifest_axml()
#     print(xml_data.get_buff().decode('utf-8'))
#
#
#     # 输出APK信息
#     print("应用程序名称:", app_name)
#     print("包名:", package_name)
#     print("版本名称:", version_name)
#     print("版本代码:", version_code)
#     print(apk.get_android_resources().get_locales(package_name))
#     print(certificates)
#     for cert_data in certificates:
#         bytes_cert_data = bytes(cert_data)
#         print('cert_data', bytes_cert_data)
#         print(type(bytes_cert_data))
#         cert = x509.load_der_x509_certificate(bytes_cert_data, default_backend())
#
#         print(cert)
# except Exception as e:
#     print("解析APK文件时出现错误:", e)

#
def calculate_md5(file_path):
    with open(file_path, "rb") as f:
        # 创建 MD5 对象
        md5_hash = hashlib.md5()

        # 逐块读取文件内容并计算 MD5 值
        while chunk := f.read(4096):  # 使用 walrus operator（:=）来避免在读取的最后一块出现空读取
            md5_hash.update(chunk)

    # 返回计算得到的 MD5 值的十六进制表示
    return md5_hash.hexdigest()

def generateHmac256Sign(body: str, timestamp: str, nonce: str) -> str:
    msg: str = body + APP_ID + timestamp + nonce
    hmacSHA256 = hmac.new(key=APP_KEY.encode('utf-8'), msg=msg.encode('utf-8'), digestmod=hashlib.sha256)
    return hmacSHA256.hexdigest()

def httpPost(path: str, body: Dict[str, Any]) -> str:
    url = 'https://openapi.sunmi.com' + path

    nonce = str(uuid.uuid4())
    body_data = json.dumps(obj=body, ensure_ascii=False)

    headers: Dict[str, str] = {}
    headers['Sunmi-Appid'] = APP_ID
    headers['Sunmi-Timestamp'] = timestamp
    headers['Sunmi-Nonce'] = nonce
    headers['Sunmi-Sign'] = generateHmac256Sign(body_data, timestamp, nonce)
    headers['Content-Type'] = 'application/json'

    response: requests.Response = requests.post(url=url, data=body_data.encode('utf-8'), headers=headers)
    if response.status_code != 200:
        raise Exception("Response signature error")

    return json.loads(response.text)


def httpPost_uploadfile(path: str, file: Dict[str, Any], body: Dict[str, Any]) -> str:
    url = 'https://openapi.sunmi.com' + path
    nonce = str(uuid.uuid4())
    param_str = json.dumps(obj=body, ensure_ascii=False)
    payload = {'params': param_str}

    headers: Dict[str, str] = {}
    headers['Sunmi-Appid'] = APP_ID
    headers['Sunmi-Timestamp'] = timestamp
    headers['Sunmi-Nonce'] = nonce
    headers['Sunmi-Sign'] = generateHmac256Sign(param_str, timestamp, nonce)

    response = requests.post(url=url, files=file, headers=headers, data=payload)
    print(response.status_code)
    if response.status_code != 200:
        raise Exception("Response signature error")

    jsonObject = json.loads(response.text)
    print(jsonObject)
    respCode = jsonObject['code']

    if respCode != 30001 and respCode != 30000:
            respSign = response.headers['Sunmi-Sign']
            respTimestamp = response.headers['Sunmi-Timestamp']
            respNonce = response.headers['Sunmi-Nonce']
            result = generateHmac256Sign(response.text, respTimestamp, respNonce) == respSign

            if not result:
                raise Exception("Response signature error")

    return json.loads(response.text)

def createApp(app_name: str, apk_uuid_data: str, cf_id_data: str, vertical_screen: list, horizontal_screen: list, icon: str, language: tuple) -> dict:
    body = {
        'app_name': app_name,
        "icon_url_uuid": icon,
        "pic_vertical_screen_uuid": vertical_screen,
        "pic_horizontal_screen_uuid": horizontal_screen,
        "apk_uuid": apk_uuid_data,
        "app_introduction": "app_introductionapp_introductionapp_introduction",
        "cf_id": cf_id_data,
        "terminals": ['P2_PRO', 'P2lite', 'P2', 'T2s', 'M2_MAX', 'P2mini', 'V2s_PLUS', 'V2s', 'P2_LITE_SE'],
        "area": [3],
        "range": 0,
        "deployment_type": 2,
        'gray_msn_list': ['V311P1A720120'],
        "language": [{"lan_id":'MnDOYOKC6xc=',"name":'English (United States)'}],
        "language_introduction": [{"lan_id":'MnDOYOKC6xc=',"introduction":'English (United States)'}],
        "remarks": "备注备注备注备注备注备注"
    }
    return httpPost('/v2/appstore/appstore/app/createApp', body)


def getApkInfo(file_path) -> dict:
    file_stream = open(file_path, 'rb')
    file = {'file': file_stream}
    md5 = calculate_md5(file_path)
    data = {
        'md5': md5,
        'file_type_key': 'appstore_apk'
    }
    print('md5 value: ', md5)
    respond = httpPost_uploadfile('/v2/midplat/filecore/file/uploadApk', file, data)
    print('uuid: ', respond['data']['uuid'])
    print('package_name: ', respond['data']['package_name'])
    return {'uuid': respond['data']['uuid'], 'package_name': respond['data']['package_name']}

def getImageUUID(file_path: str, md5, file_type: str):
    file_stream = open(file_path, 'rb')
    file = {'file': file_stream}
    data = {
        'md5': md5,
        'file_type_key': file_type
    }
    respond = httpPost_uploadfile('/v2/midplat/filecore/file/uploadImage', file, data)
    print(respond)
    return respond['data']['uuid']


def getClssifyList() -> dict:
    body = {
        'lan_type': 2
    }
    return httpPost('/v2/appstore/appstore/app/getClassifyList', body)

def get_category(name: str):
    cf_id_data = ''
    category_info = getClssifyList()['data']
    for p in category_info:
        if p.get('cf_name').strip().lower() == name:
            cf_id_data = p.get('cf_id').strip()
            break
    return cf_id_data

def get_language():
    body = {}
    respond = httpPost('/v2/appstore/appstore/app/getLanguageList', body=body)
    for p in respond['data']:
        if p['code'] == 'en_US':
            return p['lan_id'], p['en']

def getAppDetail(package_name) -> dict:
    body = {'package_name': package_name}
    return httpPost('/v2/appstore/appstore/app/getAppDetail', body)


def compress_png_to_target_size(input_path, output_path, target_size_kb):
    """
    将 PNG 图片压缩至小于目标大小（200 KB），通过调整分辨率和压缩质量。

    参数:
    - input_path: 原始图片路径
    - output_path: 压缩后图片保存路径
    - target_size_kb: 目标文件大小（KB）
    """
    with Image.open(input_path) as img:
        # 如果图片是 RGBA 格式（包含透明度），先转换为 RGB 以便处理
        if img.mode == 'RGBA':
            img = img.convert('RGB')

        # 初步保存（优化 PNG 压缩）
        img.save(output_path, format='PNG', optimize=True)
        current_size_kb = os.path.getsize(output_path) / 1024  # 获取文件大小（KB）

        # 如果文件超过目标大小，通过缩小尺寸来调整
        if current_size_kb > target_size_kb:
            scale_factor = (target_size_kb / current_size_kb) ** 0.5  # 计算缩放比例
            new_width = int(img.width * scale_factor)
            new_height = int(img.height * scale_factor)
            img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)  # 使用 LANCZOS 重采样

            # 再次保存 PNG 格式，并尝试进一步优化
            img.save(output_path, format='PNG', optimize=True)
            current_size_kb = os.path.getsize(output_path) / 1024  # 更新文件大小
        else:
            return input_path

        # 如果压缩后还是超过目标大小，继续缩小分辨率
        while current_size_kb > target_size_kb:
            new_width = int(img.width * 0.8)  # 每次缩小 20%
            new_height = int(img.height * 0.8)
            img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)

            # 重新保存图片
            img.save(output_path, format='PNG', optimize=True)
            current_size_kb = os.path.getsize(output_path) / 1024  # 更新文件大小
            print(current_size_kb)

        print(f"压缩完成: {output_path}, 大小: {current_size_kb:.2f} KB")
        return output_path


def upgradeApp(package_name, apk_uuid):
    body = {
        'package_name': package_name,
        'remarks': 'Leo Test-1 and test-2',
        'update_content': 'Added Key Information for Payment terminal',
        'update_flag': 2,
        'gray_msn_list': ['V311P1A720120'],
        'apk_uuid': apk_uuid,
        'notify_url': 'http://127.0.0.1:5001/notify'
    }
    return httpPost('/v2/appstore/appstore/app/upgradeAppVersion', body)


def uploadNewApp():
    cf_id_data = get_category('tool')

    newApp = getApkInfo(apk_path)
    apk_uuid = newApp['uuid']
    print('apk_uuid: ', apk_uuid)

    h_type = 'appstore_hscreenshot'
    screen_h_1_path = '/Users/leozhu/AndroidStudioProjects/Screen/landscape/h_1.png'
    screen_h_1 = getImageUUID(screen_h_1_path, calculate_md5(screen_h_1_path), h_type)

    screen_h_2_path = '/Users/leozhu/AndroidStudioProjects/Screen/landscape/h_2.png'
    screen_h_2 = getImageUUID(screen_h_2_path, calculate_md5(screen_h_2_path), h_type)

    screen_h_3_path = '/Users/leozhu/AndroidStudioProjects/Screen/landscape/h_3.png'
    screen_h_3 = getImageUUID(screen_h_3_path, calculate_md5(screen_h_3_path), h_type)

    h_list = [screen_h_1, screen_h_2, screen_h_3]
    print('screen_h_1: ', screen_h_1, '\n', 'screen_h_2: ', screen_h_2, '\n', 'screen_h_3: ', screen_h_3)

    v_type = 'appstore_vscreenshot'

    screen_v_1_path = '/Users/leozhu/AndroidStudioProjects/Screen/portrait/tm_1.png'
    screen_v_1_200_path = '/Users/leozhu/AndroidStudioProjects/Screen/portrait/tm_1_200kb.png'
    screen_v_1_new_path = compress_png_to_target_size(screen_v_1_path, screen_v_1_200_path, 195)
    screen_v_1 = getImageUUID(screen_v_1_new_path, calculate_md5(screen_v_1_new_path), v_type)

    screen_v_2_path = '/Users/leozhu/AndroidStudioProjects/Screen/portrait/tm_2.png'
    screen_v_2_200_path = '/Users/leozhu/AndroidStudioProjects/Screen/portrait/tm_2_200kb.png'
    screen_v_2_new_path = compress_png_to_target_size(screen_v_2_path, screen_v_2_200_path, 195)
    screen_v_2 = getImageUUID(screen_v_2_new_path, calculate_md5(screen_v_2_new_path), v_type)

    screen_v_3_path = '/Users/leozhu/AndroidStudioProjects/Screen/portrait/tm_3.png'
    screen_v_3_200_path = '/Users/leozhu/AndroidStudioProjects/Screen/portrait/tm_3_200kb.png'
    screen_v_3_new_path = compress_png_to_target_size(screen_v_3_path, screen_v_3_200_path, 195)
    screen_v_3 = getImageUUID(screen_v_3_new_path, calculate_md5(screen_v_3_new_path), v_type)

    v_list = [screen_v_1, screen_v_2, screen_v_3]
    print('screen_v_1: ', screen_v_1, '\n', 'screen_v_2: ', screen_v_2, '\n', 'screen_v_3: ', screen_v_3)

    icon_path = "/Users/leozhu/AndroidStudioProjects/Screen/icon/tm.png"  # 替换为您的图片路径
    original_image = Image.open(icon_path)
    desired_size = (144, 144)
    resized_image = original_image.resize(desired_size)
    output_path = "/Users/leozhu/AndroidStudioProjects/Screen/icon/tm_1_144_144.png"  # 替换为您想要保存的图片路径
    resized_image.save(output_path)
    icon = getImageUUID(output_path, calculate_md5(output_path), 'appstore_icon')
    print('icon: ', icon)

    print(get_language())

    final = createApp(apk_name, apk_uuid, cf_id_data, v_list, h_list, icon, get_language())
    print(final)

# uploadNewApp()


# updated_apk_path = '/Users/leozhu/Downloads/Leo Terminal Management-debug.apk'
# upgradedApp = getApkInfo(updated_apk_path)
# updated_apk_uuid = upgradedApp['uuid']
# updated_apk_name = upgradedApp['package_name']
# updateApk = upgradeApp(updated_apk_name, updated_apk_uuid)
# print(updateApk)



# url = "https://webapi.sunmi.com/v3/dmp/appstore-jobs/public/callback/MyCallbackTesturl"
# url = "https://cloud-api-dev.pecanpos.com/public/sunmi/review/result"
url = 'http://127.0.0.1:5001/notify'
headers = {
    "Content-Type": "application/json"
}

data = {
    "package_name": "updated_apk_name",
    "audit_state": 1,
    "audit_result": "",
    "audit_type": 2
}

response = requests.post(url, headers=headers, json=data)

print("Response Status Code:", response.status_code)
print("Response Body:", response.text)




# import base64
# import hashlib
# import hmac
# import json
# import os
# import requests
# import time
# import uuid
# import rsa
#
#
#
# appId: str = '2ce40c7a922346e48bfa90d6bafedf3e'
# appKey: str = '4918e232e0594106b2b62652cd7d85c6'
#
# appPrivateKey = ''
# sunmiPublicKey = ''
#
#
#
# def uploadFile(url, filePath, params, signType):
#     file = open(filePath, 'rb')
#     files = {'file': file}
#     payload = {'params': params}
#     print(payload)
#     headers = {
#         'Sunmi-Appid': appId,
#         'Sunmi-Timestamp': str(int(time.time())),
#         'Sunmi-Nonce': str(uuid.uuid4()),
#     }
#     if signType == "RSA":
#         headers['Sunmi-Sign'] = generateRsa2048Sign(
#             appId, appPrivateKey, headers['Sunmi-Timestamp'], headers['Sunmi-Nonce'], params
#         )
#     else:
#         headers['Sunmi-Sign'] = generateHmac256Sign(
#             appId, appKey, headers['Sunmi-Timestamp'], headers['Sunmi-Nonce'], params
#         )
#         print('2', headers['Sunmi-Sign'])
#
#     response = requests.post(url, headers=headers, files=files, data=payload)
#     print(response.status_code)
#
#     if response.status_code != 200:
#         raise Exception("Response signature error")
#
#     respBody = response.text
#
#     # Verify response signature
#     jsonObject = json.loads(respBody)
#     print(jsonObject)
#     respCode = jsonObject['code']
#     if respCode != 30001 and respCode != 30000:
#         respSign = response.headers['Sunmi-Sign']
#         respTimestamp = response.headers['Sunmi-Timestamp']
#         respNonce = response.headers['Sunmi-Nonce']
#
#         if signType == "RSA":
#             result = verifyRsa2048Sign(
#                 appId, sunmiPublicKey, respSign, respTimestamp, respNonce, respBody
#             )
#         else:
#             result = generateHmac256Sign(
#                 appId, appKey, respTimestamp, respNonce, respBody
#             ) == respSign
#
#         if not result:
#             raise Exception("Response signature error")
#
#     return respBody
#
# def generateHmac256Sign(appId, appKey, timestamp, nonce, params):
#     content = params + appId + timestamp + nonce
#     hmacSHA256 = hmac.new(appKey.encode(), msg=content.encode(), digestmod=hashlib.sha256)
#     return hmacSHA256.hexdigest()
#
# def generateRsa2048Sign(appId, privateKey, timestamp, nonce, params):
#     content = params + appId + timestamp + nonce
#     priKey = base64.b64decode(privateKey)
#     key = rsa.PrivateKey.load_pkcs1(priKey)
#     signature = rsa.sign(content.encode(), key, 'SHA-256')
#     return base64.b64encode(signature).decode()
#
# def verifyRsa2048Sign(appId, publicKey, sign, timestamp, nonce, params):
#     content = params + appId + timestamp + nonce
#     pubKey = base64.b64decode(publicKey)
#     key = rsa.PublicKey.load_pkcs1_openssl_pem(pubKey)
#     signature = base64.b64decode(sign)
#     try:
#         rsa.verify(content.encode(), signature, key)
#         return True
#     except rsa.pkcs1.VerificationError:
#         return False
#
#
# data = {
#         'md5': '535b8ff1b8c91c72bbae3ed124da7355',
#         'file_type_key': 'appstore_hscreenshot'
#     }
# params = json.dumps(obj=data, ensure_ascii=False)
# res = uploadFile(
#     'https://openapi.sunmi.com//v2/midplat/filecore/file/uploadImage',
#     '/Users/leozhu/AndroidStudioProjects/Screen/horizontal/h_1.png', params, 'AppKey')
# print(res)
# res_json = json.loads(s=res)
# apk_uuid = res_json['data']['uuid']
# package_name = res_json['data']['package_name']
# print('apk_uuid', apk_uuid)
# print('package_name', package_name)