import socket

def connect_and_leak(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(b'hello')
    data = s.recv(1024)
    return data

def connect_and_close(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    try:
        s.send(b'hello')
        data = s.recv(1024)
        return data
    finally:
        s.close()
