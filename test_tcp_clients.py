# test_tcp_clients.py
import socket, time
for i in range(50):
    try:
        s = socket.socket()
        s.settimeout(0.2)
        s.connect(('127.0.0.1', 80))  # connect to local host port 80 (may fail; that's fine)
    except Exception:
        pass
    finally:
        try: s.close()
        except: pass
    time.sleep(0.05)
print('done test traffic')
