# -*- coding: utf-8 -*-

import hashlib
import hmac
import json
import random
import requests
import time
import datetime
from typing import Any, Dict, List, Tuple
import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

import smtplib
from email.mime.text import MIMEText
from email.header import Header

CPUPercentage = []
memoryPercentage = []

pauseTime = 30

def get_time():
    # 获取当前时间
    current_time = datetime.datetime.now()
    # 格式化时间为"月日年时分"
    formatted_time = current_time.strftime("%m%d%y%H%M")
    return formatted_time

# 添加数据点的函数
def add_data_point(x, y):
    x_data.append(x)
    y_data.append(y)
    line.set_xdata(x_data)
    line.set_ydata(y_data)
    ax.relim()
    ax.autoscale_view()
    plt.draw()
    plt.pause(30)  # 暂停一小段时间以便更新图表


def send_Email(title, message):
    # 邮件内容
    msg = MIMEText(message, 'plain', 'utf-8')
    msg['From'] = 'Sunmi_Leo Testing'
    msg['To'] = 'Client'
    msg['Subject'] = Header(title, 'utf-8')

    # 发送邮件
    try:
        # 连接Gmail SMTP服务器
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

        # 登录到你的Gmail账户
        server.login('leotyzhu@gmail.com', 'gweaehzprmwtirwx')

        # 发送邮件
        server.sendmail('leotyzhu@gmail.com', 'leo.zhu@sunmi.us', msg.as_string())

        print('Send Success')
    except Exception as e:
        print('send Failure:', e)
    finally:
        # 关闭连接
        server.quit()


# 初始化图表
plt.ion()  # 开启交互模式
fig, ax = plt.subplots()
x_data, y_data = [datetime.datetime.now()], [1]
line, = ax.plot(x_data, y_data, label='Memory Percentage')

# 使用日期格式化器设置X轴的格式
date_format = mdates.DateFormatter('%m%d%y%H%M')
ax.xaxis.set_major_formatter(date_format)

# 设置X轴标签旋转，以便更好地适应
plt.xticks(rotation=45)

# Add title and lab
ax.set_title('Memory Usage')
ax.set_xlabel('Time')
ax.set_ylabel('Memory Percentage')


sn = ['PC04D29U00102']

# Replace the applied APPID&APPKEY
APP_ID: str = '2ce40c7a922346e48bfa90d6bafedf3e'
APP_KEY: str = '4918e232e0594106b2b62652cd7d85c6'
timestamp = str(int(time.time()))

def generateSign(body: str, timestamp: str, nonce: str) -> str:
    msg: str = body + APP_ID + timestamp + nonce
    return hmac.new(key=APP_KEY.encode('utf-8'), msg=msg.encode('utf-8'),
                    digestmod=hashlib.sha256).hexdigest()



def httpPost(path: str, body: Dict[str, Any]) -> str:
    url = 'https://openapi.sunmi.com' + path

    nonce = '{:06d}'.format(random.randint(0, 999999))

    body_data = json.dumps(obj=body, ensure_ascii=False)

    headers: Dict[str, str] = {}
    headers['Sunmi-Appid'] = APP_ID
    headers['Sunmi-Timestamp'] = timestamp
    headers['Sunmi-Nonce'] = nonce
    headers['Sunmi-Sign'] = generateSign(body_data, timestamp, nonce)
    headers['Source'] = 'openapi'
    headers['Content-Type'] = 'application/json'

    response: requests.Response = requests.post(url=url, data=body_data.encode('utf-8'), headers=headers)

    return json.loads(response.text)

def onlinestatus(sn_list) -> dict:
    body = {'msn_list': sn_list}
    return httpPost('/v2/mdm/open/open/device/onlineStatus', body)

def location(sn_single) -> dict:
    body = {'msn': sn_single}
    return httpPost('/v2/mdm/open/open/device/position', body)

def clearscreenpwd(sn_list) -> dict:
    body = {'msn_list': sn_list}
    return httpPost('/v2/mdm/open/open/cmd/clearScreenPwd', body)

def realtimeinfo(sn_single) -> dict:
    body = {'msn': sn_single}
    return httpPost('/v2/mdm/open/open/device/realTimeInfo', body)


# res = onlinestatus(sn)['data']['list']
res = onlinestatus(sn)
res_json = json.dumps(res)
f1 = open('parameter.json', 'w')
f1.write(res_json)
f1.close()
# for p in result:
#     if p['status'] == 0:
#         print(p)



print(httpPost('/v2/mdm/open/open/device/applyControl', {'msn': 'PC04D29U00102'}))
# print(location('PC04D29U00102'))

testDevice = ['PC04D29U00102']
threshold = '65%'
while True:
    try:
        for sn in testDevice:
            realTimeInfo = realtimeinfo(sn)
            print(realTimeInfo)
            code = realTimeInfo['code']
            if code == 1:
                allInfo = realTimeInfo['data']['running']

                CPUPercent = allInfo['cpercent']
                CPUPercentage.append(CPUPercent)

                mPercent = allInfo['mpercent']
                memoryPercentage.append(mPercent)

                print('SN: ' + sn + '\n' + 'CPU Percentage: ' + CPUPercent + '\n' + 'Memory Percentage: ' + mPercent)

                # 添加数据点到图表
                add_data_point(datetime.datetime.now(), float(mPercent.strip('%')))

                if mPercent >= threshold:
                    os.system('say --voice=Samantha "Memory Percentage Is High"')
                    message = 'Dear Client, \nCurrently, your terminal (' + sn + ') has high memory percentage. \n' \
                              + 'CPU Percentage: ' + CPUPercent + '\n' \
                              + 'Memory Percentage: ' + mPercent \
                              + '\n'
                    # send_Email('Memory Leaking', message)
                print('')
            else:
                print('Error Message: ' + realTimeInfo['message'] + '\n')
                pass
        time.sleep(pauseTime)

    except KeyboardInterrupt:
        # 如果使用 Ctrl+C 中断程序，可以在这里进行处理
        print('Keyboard Interrupt')
        print('All Memory Percentage: ' + memoryPercentage + 'All CPU Percentage: ' + CPUPercentage)
        plt.ioff()  # 关闭交互模式
        plt.show()