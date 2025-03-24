import socket
import time
import json

HOST = 'localhost'
PORT_VEH = 5005
PORT_RA  = 5000

my_data = ["Long_Term_Certif", "LA1_C", "LA2_C"]
data_json = json.dumps(my_data)

def send(port,binary_msg):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, port))
            s.sendall(binary_msg)
            return 1
    
def listen(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen(1) #nb de conx
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            return data
    

if __name__ == '__main__':
    print("send msg to RA: ", my_data)
    send(PORT_RA,data_json.encode('utf-8'))
    time.sleep(1)
    pc=listen(PORT_VEH)
    print(pc.decode('utf-8'))
    
