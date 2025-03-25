from abc import abstractmethod
import threading
from typing import override
from cryptography.hazmat.primitives.asymmetric import ec
import socket
import time

class Address:
    def __init__(self, ip_address, Port):
        self.ip_address:str = ip_address
        self.Port:int = Port

class mini_packet:
    def __init__(self, address: Address, data):
        self.address:Address = address
        self.data = data

class Entity:

    def __init__(self, address: Address):
        self.__Private_Key=ec.generate_private_key(ec.SECP256R1())
        self.__Public_Key=self.__Private_Key.public_Key()
        self.address=address
        self.connected_Entities: dict[str,Entity]={}
        self.buffer:list[mini_packet]=[]

    def send(destination: 'Entity',binary_msg: bin):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((destination.address.ip_address, destination.address.Port))
            s.sendall(binary_msg)
            return 1
    
    # this fnct maybe will not be in use 
    def listen(address: Address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            s.listen(100)
            conn, addr = s.accept()
            with conn:
                data = conn.recv(4096)
                return addr,data
    
    def listen_and_fill_buffer(self,address: Address, buffer: list[mini_packet]):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            while True:
                s.listen(100)
                conn, addr = s.accept()
                source_address:Address=None
                source_address.ip_address,source_address.Port=addr
                with conn:
                    data = conn.recv(4096)
                    packet:mini_packet=None
                    packet.address,packet.data=source_address,data
                    self.buffer.append(packet)
    
    def get_Public_Key(self):
        return self.__Public_Key

    def get_Exchanged_Key(this,entity:"Entity"):
        return this.__Private_Key.exchange(ec.ECDH(), entity.get_Public_Key())

    #To see later
    def encrypt_message():
        pass
    
    #To see later
    def decrypt_received_msg(data,addr):
        pass
    
    def get_msg_Entity_source(self,address:Address):
        #On traite notre cas ou juste les port sont differents
        for name,entity in self.connected_Entities.items():
            if address.Port == entity.address.Port:
                return name
        return None
    
    """
    @abstractmethod
    def packet_forwarding(self):
        pass

    @abstractmethod
    def start(self):
        pass
    """
    # A ne pas décommenter pour le moment
    """
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
    """


class  Registration_Authority (Entity):
    def __init__(self, address):
        super().__init__(address)
        self.connected_vehicule=0
    
    def add_LA1(self, LA):
        self.connected_Entities["LA1"]=LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"]=LA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"]=PCA

    def add_LTCA(self, LTCA):
        self.connected_Entities["LTCA"]=LTCA

    def add_vehicule(self, VEH):
        self.connected_vehicule+=1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)]=VEH

    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        if source_entity == None:
            pass    #The source of the packet is not known
        elif source_entity == "LA1":
            pass # implement a fonction waiting LA2
        elif source_entity == "LA2":
            pass # implement a fonction waiting la LA1
        elif source_entity == "LTCA":
            pass # implement a fonction verifing the reponse of LTCA and then forwarding to LA1 and LA2
        elif source_entity == "PCA":
            pass # implement a fonction that forward the data to VEH
        else:   #the entity is a vehicule implement then a fonction to send LTC in data to LTCA
            pass
    
    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.address,self.buffer,))
        listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()


class Link_Authority (Entity):
    def __init__(self, address):
        super().__init__(address)
        self.connected_vehicule=0

    def add_RA(self, RA):
        self.connected_Entities["RA"]=RA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"]=PCA

    def add_vehicule(self, VEH):
        self.connected_vehicule+=1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)]=VEH

    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        if source_entity == "RA":
            pass 
        else:   #The source of the packet is not known
            pass
    
    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.address,self.buffer,))
        listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()


class Pseudo_Certificate_Authority (Entity):
    def __init__(self, address):
        super().__init__(address)
        self.connected_vehicule=0
    
    def add_LA1(self, LA):
        self.connected_Entities["LA1"]=LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"]=LA

    def add_RA(self, RA):
        self.connected_Entities["RA"]=RA
    
    def add_vehicule(self, VEH):
        self.connected_vehicule+=1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)]=VEH


    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        if source_entity == "RA":
            pass
        else:   #the unknown
            pass
    
    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.address,self.buffer,))
        listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()





class Long_Term_Certificate_Authority (Entity):
    def __init__(self, address):
        super().__init__(address)
        self.connected_vehicule=0

    def add_PCA(self, RA):
        self.connected_Entities["RA"]=RA
    
    def add_vehicule(self, VEH):
        self.connected_vehicule+=1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)]=VEH


    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        if source_entity == "RA":
            pass
        else:   #the source is unknown
            pass
    
    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.address,self.buffer,))
        listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()




class vehicule (Entity):
    def __init__(self, address):
        super().__init__(address)
    
    def add_LA1(self, LA):
        self.connected_Entities["LA1"]=LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"]=LA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"]=PCA

    def add_LTCA(self, LTCA):
        self.connected_Entities["LTCA"]=LTCA

    def add_RA(self, RA):
        self.connected_Entities["RA"]=RA

    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        if source_entity == "RA":
            pass
        else:
            pass    #The source of the packet is not unknown
    
    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.address,self.buffer,))
        listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()

