import socket
import threading
# import de "our_cryptage.py"
import our_cryptage


# Configuration Proxy
PROXY_IP = '0.0.0.0' #L'ip de notre proxy, ici '0.0.0.0' veut dire que le proxy est accessible depuis n'importe quelle interface réseau de la machine
PROXY_PORT = 12343 #Le port sur lequel le proxy va écouter
BUFFER_SIZE = 4096 #Taille du buffer de réception
PROXY_OUTPUT_IP = 'localhost' #L'ip de la machine sur laquelle tourne le proxy de sortie
PROXY_OUTPUT_PORT = 12345 #Le port sur lequel le proxy de sortie écoute


#Configuration Encryption / Decryption
ENCRYPTION_KEY_SYMETRIQUE = '' #La clé de cryptage/décryptage symetrique


def handle_client(client_socket, client_addr): #Fonction qui va gérer la connexion initiale avec le client
    request = b''
    while True:
        data = client_socket.recv(BUFFER_SIZE) #On récupère la requête du client
        request += data
        if len(data) < BUFFER_SIZE: #Si la taille de la requête est inférieure à la taille du buffer, on a reçu toute la requête
            break
    request_line = request.split(b'\n')[0].decode('utf-8') #On récupère la première ligne de la requête
    method, url, _ = request_line.split() #On récupère la méthode, l'url et le protocole de la requête
    if method == "CONNECT": #Si la méthode est CONNECT, on appelle la fonction handle_connect_methode
        handle_connect_methode(client_socket, url, request)
    else: #Sinon, on appelle la fonction handle_classic_request
        handle_classic_request(client_socket, request)

def check_if_secure_connection_open():
    # Fonction qui va vérifier si une connexion sécurisée est déjà ouverte avec le proxy distant
    # Si c'est le cas, on retourne true, sinon on retourne false
    if our_cryptage.getSymetricKey() == None:
        return False

    message = "Ping"
    message = message.encode('utf-8')
    message_crypte = our_cryptage.cryptage(message)
    output_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    output_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT))
    output_socket.sendall(message_crypte)
    output_socket.setblocking(0)
    try:
        response = output_socket.recv(BUFFER_SIZE)
        response = our_cryptage.decryptage(response)
        if response == b"Pong":
            return True
        else:
            start_secure_session()
            return True

    except socket.error:
        return False



def handle_connect_methode(client_socket, url, request):
    # Fonction qui va gérer la connexion avec le client si la méthode est CONNECT, c'est à dire si le client veut se connecter à un site en https (donc avec un certificat ssl)
    # Dans ce cas là, on vas maintenir la connexion aves le proxy distant
    try:
        output_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        output_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT)) #On se connecte au proxy de sortie

        #TODO: on doit crypter la requête avant de l'envoyer au proxy de sortie
        output_socket.sendall(request) #On envoie la requête au proxy de sortie

        output_socket.setblocking(0) #On met les sockets en mode non bloquants pour pouvoir gerer les deux sockets en même temps
        client_socket.setblocking(0)


        while True:
            try:
                request = client_socket.recv(BUFFER_SIZE) #On récupère la requête du client
                if not request: #Si la requête est vide, on ne fait rien
                    break
                #TODO: La il faudrait crypter la requète!!!!!

                output_socket.sendall(request) #On envoie la requête au proxy de sortie
            except socket.error:
                pass

            try:
                response = output_socket.recv(BUFFER_SIZE) #On récupère la réponse du proxy de sortie
                if not response: #Si la réponse est vide, on ne fait rien
                    break
                #TO DO: La il faudrait décrypter la réponse!!!!!
                client_socket.sendall(response) #On envoie la réponse au client
            except socket.error:
                pass

    except Exception as e:
        print(f"Erreur lors de la connexion: {e}")

    finally:
        client_socket.close() #On ferme la connexion avec le client et le proxy de sortie
        output_socket.close()

def handle_classic_request(client_socket, request):
    # Fonction qui va gérer la connexion avec le client si la méthode n'est pas CONNECT, c'est à dire si le client veut se connecter à un site en http
    output_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #On se connecte au proxy de sortie
    output_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT))
    #TODO: on doit crypter la requête avant de l'envoyer au proxy de sortie
    output_socket.sendall(request) #On envoie la requête au proxy de sortie
    response = output_socket.recv(BUFFER_SIZE)
    #TODO: La il faudrait décrypter la réponse!!!!!
    client_socket.sendall(response)
    client_socket.close()
    output_socket.close()


def start_secure_session():
    #Fonction qui va démarrer une session sécurisée avec le proxy de sortie
    #TODO: On envoie un message (non crypté) au proxy de sortie "START_SECURE_SESSION"
    #TODO: On attend de recevoir un message du proxy de sortie "READY"
    #TODO: On genère notre clé privée et publique pour le proxy d'entrée qui vas permettre d'echanger la clé symetrique de facons securisé
    #TODO: On envoie notre clé publique au proxy de sortie
    #TODO: On attend de recevoir la clé symetrique founrit par le proxy de sortie (cryptée que l'on doit decrypter avec notre clé privée)
    #TODO: On decrypte la clé symetrique avec notre clé privée
    #TODO: On envoie un message au proxy de sortie "OK" (crypté avec la clé symétrique)
    #TODO: On attend de recevoir un message du proxy de sortie
    #TODO: On decrypte le message avec la clé symétriquea
    #TODO: Si le message est "OK", on retourne True et la clé symetrique de cryptage/décryptage
    #TODO: Sinon, on retourne False et None

    #TODO: return bool (True si la session est démarrée, False sinon) et la clé de cryptage/décryptage symetrique (si la session est démarrée)
    pass

def exchange_keys():
    #Fonction qui va échanger les clés entre le proxy d'entrée et le proxy de sortie
    pass

def generate_keys():
    #Fonction qui va générer les clés de cryptage/décryptage
    pass




def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((PROXY_IP, PROXY_PORT))
    server.listen(50)
    print(f"Proxy d'entrée en écoute sur {PROXY_IP}:{PROXY_PORT}")

    while True:
        client_socket, client_addr = server.accept()
        print(f"Requête reçue de {client_addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_addr))
        client_handler.start()

if __name__ == '__main__':
    main()
