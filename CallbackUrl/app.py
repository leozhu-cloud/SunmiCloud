from flask import Flask, request

app = Flask(__name__)

# 用于保存最新收到的回调数据
latest_data = ""

@app.route('/')
def hello():
    return 'Hello from AlphaZ'
@app.route('/notify', methods=['GET', 'POST'])
def notify():
    global latest_data
    if request.method == 'POST':
        data = request.data.decode('utf-8')  # 获取原始回调内容/
        print("Received raw callback:", data)
        latest_data = data
        return "", 200  # 返回 200 OK，不带任何 JSON 响应
    else:
        # 如果是 GET 请求
        return f"<h3>最近一次收到的通知内容:</h3><pre>{latest_data}</pre>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)  # 监听所有 IP，端口 5001