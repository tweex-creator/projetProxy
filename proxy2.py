import socket
import threading

# Configuration
PROXY_OUTPUT_IP = 'localhost'
PROXY_OUTPUT_PORT = 12345
BUFFER_SIZE = 4096

def handle_client(client_socket, client_addr):
    # Fonction qui va gérer la connexion avec le client
    request = b''
    while True:
        data = client_socket.recv(BUFFER_SIZE) #On récupère la requête du client
        request += data
        if len(data) < BUFFER_SIZE: #Si la taille de la requête est inférieure à la taille du buffer, on a reçu toute la requête
            break



    #TODO: La il faut décrypter la requête
    request_line = request.split(b'\n')[0].decode('utf-8') #On récupère la première ligne de la requête
    method, url, _ = request_line.split() #On récupère la méthode, l'url et le protocole de la requête
    print(request_line, method, url)

    if method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]: #Si la méthode est une méthode classique, on appelle la fonction handle_classic_request
        process_request(client_socket, request)
    elif method == "CONNECT": #Si la méthode est CONNECT, on appelle la fonction handle_connect_methode
        process_connect(client_socket, url)
    else:
        response = b'HTTP/1.1 405 Method Not Allowed\r\n\r\n' #Si la méthode n'est pas supportée, on envoie une erreur 405
        #TODO : crypter la réponse
        client_socket.sendall(response)
        client_socket.close()


def process_connect(client_socket, url):
    # Fonction qui va gérer la connexion avec le client si la méthode est CONNECT, c'est à dire si le client veut se connecter à un site en https,
    # dans ce cas, on doit maintenir la connexion avec le client et le site distant
    target_host, target_port = url.split(':')  # On récupère l'adresse du site distant et le port
    target_port = int(target_port) # On convertit le port en entier

    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((target_host, target_port))
        client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n') #On envoie une réponse 200 au client pour lui dire que la connexion est établie

        remote_socket.setblocking(0) #On met les sockets en mode non bloquant pour pouvoir les utiliser en même temps
        client_socket.setblocking(0)

        while True:
            try:
                request = client_socket.recv(BUFFER_SIZE) #On récupère les données envoyées par le client (via le proxy d'entrée)
                #TODO: Il faut décrypter les données
                if not request:
                    break
                remote_socket.sendall(request) #On envoie les données au site distant
            except socket.error:
                pass

            try:
                response = remote_socket.recv(BUFFER_SIZE) #On récupère les données envoyées par le site distant
                if not response:
                    break
                #TODO: Il faut crypter les données
                client_socket.sendall(response) #On envoie les données au client (via le proxy d'entrée)
            except socket.error:
                pass

    except Exception as e:
        print(f"Erreur lors de la connexion: {e}")

    finally:
        client_socket.close() #On ferme les sockets
        remote_socket.close()

def process_request(client_socket, request):
    request_line = request.split(b'\n')[0].decode('utf-8') #On récupère la première ligne de la requête (deja decrypter dans la fonction handle_client)
    method, url, _ = request_line.split() #On récupère la méthode, l'url et le protocole de la requête

    url_data = url.split('/', 3)  # On récupère l'adresse du site distant et le chemin de la ressource demandée(3 pour ne pas avoir de / en trop, si l'url est http://www.google.fr, on aura ['http:','', 'www.google.fr', ''])
    if len(url_data) < 4: #Si l'url n'est pas correcte, on envoie une erreur 400 au client (via le proxy d'entrée)
        client_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
        client_socket.close()
        return

    target_host = url_data[2] #On récupère l'adresse du site distant
    target_url = '/' + url_data[3] #On récupère le chemin de la ressource demandée

    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_socket.connect((target_host, 80)) #On se connecte au site distant sur le port 80

    #modified_request = request.replace(url.encode('utf-8'), target_url.encode('utf-8'), 1)
    #target_socket.sendall(modified_request)
    target_socket.sendall(request) #On envoie la requête au site distant


    response = b''
    while True:
        data = target_socket.recv(BUFFER_SIZE) #On récupère la réponse du site distant,
        response += data
        if len(data) < BUFFER_SIZE: #Si la taille des données est inférieure à la taille du buffer, on a reçu toute la réponse
            break

    #TODO: Il faut crypter la réponse
    client_socket.sendall(response)

    client_socket.close()
    target_socket.close()


def start_secure_session():
    #TODO: Envoie un message au proxy d'entrée pour lui dire qu'on veut se connecter, c'est lui qui vas alors lancer la connexion securisée
    pass

def handle_start_secure_session_request(client_socket):
    #TODO: On genère notre clé privée et publique
    #TODO: Attendre de recevoir un message du proxy d'entrée qui contient ca clé publique
    #TODO: On envoie notre clé publique au proxy d'entrée
    #TODO: Attendre de recevoir un message du proxy d'entrée qui contient ca clé symetrique chiffré avec notre clé public
    #TODO: On déchiffre la clé symetrique avec notre clé privée
    #TODO: On envoie un message au proxy d'entrée "OK" pour lui dire que la connexion est établie en le chiffrant avec la clé symetrique
    #TODO: On attend de recevoir un message "OK" du proxy d'entrée crypté avec la clé symetrique
    #TODO: On envoie un message "OK" au proxy d'entrée crypté avec la clé symetrique
    #TODO: On peut maintenant envoyer des données cryptées au proxy d'entrée
    pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT))
    server.listen(50)
    print(f"Proxy de sortie en écoute sur {PROXY_OUTPUT_IP}:{PROXY_OUTPUT_PORT}")

    while True:
        client_socket, client_addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_addr))
        client_handler.start()

if __name__ == '__main__':
    main()
