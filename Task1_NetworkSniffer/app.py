from flask import Flask, render_template
from flask_socketio import SocketIO
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'networksniffer2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

@app.route('/')
def index():
    return render_template('dashboard.html')

def start_sniffer():
    from sniffer import start_sniffing
    start_sniffing(socketio)

if __name__ == '__main__':
    sniffer_thread = threading.Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()
    print("🚀 Network Sniffer running at http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)