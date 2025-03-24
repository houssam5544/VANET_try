import socket
import time

HOST = 'localhost'
PORT_PCA = 5003
PORT_LA1 = 5001
PORT_RA  = 5000

def send(port,binary_msg):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, port))
            s.sendall(binary_msg)
            return 1
    
def listen(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen() #nb de conx
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            return data
    

if __name__ == '__main__':
    ra_msg=listen(PORT_LA1).decode('utf-8')
    print("message from RA: ", ra_msg)
    time.sleep(1)
    msg='PL1'
    print("send msg to RA: ", msg)
    send(PORT_RA, msg.encode('utf-8'))
