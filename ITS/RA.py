import json
import socket
import time

HOST = 'localhost'
PORT_PCA = 5003
PORT_LA1 = 5001
PORT_LA2 = 5002
PORT_RA  = 5000
PORT_LTCA= 5004
PORT_VEH = 5005

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
    veh=listen(PORT_RA)
    data=json.loads(veh.decode('utf-8'))
    print("message from vehicule: ",data)
    time.sleep(1)

    print("send msg to LTCA: ", data[0])
    send(PORT_LTCA,data[0].encode('utf-8'))
    time.sleep(1)
    ltca=listen(PORT_RA).decode('utf-8')
    print("msg from LTCA: ",ltca)

    time.sleep(1)
    print("send msg to LA1: ", data[1])
    send(PORT_LA1,data[1].encode('utf-8'))
    time.sleep(1)
    la1=listen(PORT_RA).decode('utf-8')
    print("msg from LA1: ",la1)

    time.sleep(1)
    print("send msg to LA2: ", data[2])
    send(PORT_LA2,data[2].encode('utf-8'))
    time.sleep(1)
    la2=listen(PORT_RA).decode('utf-8')
    print("msg from LA2: ",la2)

    pca_data_seg=[la1,la2]
    pca_data_seg=json.dumps(pca_data_seg)
    time.sleep(1)
    print("send msg to PCA: ", pca_data_seg)
    send(PORT_PCA,pca_data_seg.encode('utf-8'))
    time.sleep(1)
    PC=listen(PORT_RA).decode('utf-8')
    print("msg from PCA: ",PC)

    time.sleep(1)
    print("send msg to Vehicule: ", PC)
    send(PORT_VEH,PC.encode('utf-8'))
    time.sleep(1)



