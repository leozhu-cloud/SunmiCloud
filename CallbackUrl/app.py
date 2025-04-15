from flask import Flask, request

app = Flask(__name__)

@app.route('/notify', methods=['POST'])
def notify():
    data = request.data  # 获取原始回调内容/
    print("Received raw callback:", data.decode('utf-8'))

    # 记录回调内容
    with open("callback_raw.txt", "aa") as log_file:
        log_file.write(data.decode('utf-8') + "\n")

    return "", 200  # 返回 200 OK，不带任何 JSON 响应

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)  # 监听所有 IP，端口 5000