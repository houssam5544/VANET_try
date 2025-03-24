import socket
import time

class Address:
    def __init__(self, ip_address, Port):
        self.ip_address = ip_address
        self.Port = Port

class Entity:
    def __init__(self, Public_Key, Private_Key, address):
        self.__Private_Key=Private_Key
        self.Public_Key=Public_Key
        self.address=address

    def send_request(address:Address, binary_msg):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((address.ip_address, address.Port))
            s.sendall(binary_msg)
            return 1
    
    def listen_for_response(address:Address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            s.listen() #nb de conx
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024)
            s.close()
            return data
        
    def send_and_listen(self,address:Address, binary_msg):
        self.send_request(address, binary_msg)
        time.sleep(1)
        return  self.listen_for_response(address)


class Root_Authority (Entity):
    def __init__(self, Public_Key, Private_Key, Port):
        super().__init__(self, Public_Key, Private_Key, Port)
        self.LA=[]
        self.PCA=None
        self.LTCA=None
    
    def add_LA(self, LA):
        self.LA(LA)

    def add_PCA(self, PCA):
        self.PCA=PCA

    def add_PCA(self, LTCA):
        self.LTCA=LTCA

class Link_Authority (Entity):
    def __init__(self, Public_Key, Private_Key, Port):
        super().__init__(self, Public_Key, Private_Key, Port)
        self.RA=None
        self.PCA=None

    def add_RA(self, RA):
        self.RA(RA)

    def add_PCA(self, PCA):
        self.PCA=PCA
    
class Pseudo_Certificate_Authority (Entity):
    def __init__(self, Public_Key, Private_Key, Port):
        super().__init__(self, Public_Key, Private_Key, Port)
        self.LA=[]
        self.RA=None

    def add_RA(self, RA):
        self.RA(RA)

    def add_PCA(self, LA):
        self.LA=LA


class Long_Term_Certificate_Authority (Entity):
    def __init__(self, Public_Key, Private_Key, Port):
        super().__init__(self, Public_Key, Private_Key, Port)
        self.RA=None

    def add_RA(self, RA):
        self.RA(RA)


class vehicule (Entity):
    def __init__(self, Public_Key, Private_Key, Port):
        super().__init__(self, Public_Key, Private_Key, Port)
        self.RA=None

    def add_RA(self, RA):
        self.RA(RA)