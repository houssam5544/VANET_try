import socket
import time

HOST = 'localhost'
PORT_SEND = 5002  # Port sur lequel program2 écoute pour recevoir la requête
PORT_LISTEN = 5001  # Port sur lequel program1 va écouter pour la réponse

def send_request():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT_SEND))
        message = b"Hello from program1!"
        s.sendall(message)
        print("Program1: Requête envoyée à program2.")

def listen_for_response():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_LISTEN))
        s.listen(1)
        print("Program1: En écoute sur le port", PORT_LISTEN, "pour une réponse...")
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            print("Program1: Réponse reçue :", data)

if __name__ == '__main__':
    # Envoyer la requête, puis fermer la connexion
    send_request()
    
    # Pause pour être certain que program2 est prêt à envoyer la réponse
    time.sleep(1)
    
    # Se mettre en écoute pour recevoir la réponse
    listen_for_response()
