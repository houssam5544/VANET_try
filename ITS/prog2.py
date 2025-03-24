import socket
import time

HOST = 'localhost'
PORT_LISTEN = 5002  # Port sur lequel program2 va écouter pour recevoir la requête
PORT_SEND = 5001    # Port sur lequel program1 écoute pour recevoir la réponse

def listen_for_request():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_LISTEN))
        s.listen(1)
        print("Program2: En écoute sur le port", PORT_LISTEN, "pour la requête...")
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            print("Program2: Requête reçue :", data)

def send_response():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT_SEND))
        message = b"Hello from program2!"
        s.sendall(message)
        print("Program2: Réponse envoyée à program1.")

if __name__ == '__main__':
    # Se mettre en écoute pour recevoir la requête
    listen_for_request()
    
    # Pause pour être certain que program1 est prêt à recevoir la réponse
    time.sleep(1)
    
    # Envoyer la réponse puis fermer la connexion
    send_response()
