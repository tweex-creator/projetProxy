import socket
import threading
import time

from Crypto.PublicKey import RSA

import our_cryptage

# Configuration
PROXY_OUTPUT_IP = 'localhost'
PROXY_OUTPUT_PORT = 12345
BUFFER_SIZE = 4096

def handle_client(client_socket, client_addr):
    # Fonction qui va gérer la connexion avec le client
    request_coded = b''
    while True:
        data = client_socket.recv(BUFFER_SIZE) #On récupère la requête du client
        request_coded += data
        if len(data) < BUFFER_SIZE: #Si la taille de la requête est inférieure à la taille du buffer, on a reçu toute la requête
            break

    try:
        # On vérifie si le client est notre proxy d'entré qui veut démarrer une session, on le fait avant de décrypter la requête
        if "START_SECURE_SESSION" in request_coded.decode('utf-8'):
            # Si le client est notre proxy d'entré qui veut démarrer une session, on appelle la fonction handle_start_session
            handle_start_secure_session_request(client_socket)
            client_socket.close()
            return
    except:
        pass

    # On décrypte la requête
    request = our_cryptage.decryptage(request_coded)
    if request == None:
        client_socket.close()
        return

    if "Ping" in request.decode('utf-8'):
        # Si le client est notre proxy de sortie qui veut vérifier si la connexion est toujours ouverte, on renvoie Pong
        message = "Pong"
        message = message.encode('utf-8')
        message_crypte = our_cryptage.cryptage(message)
        client_socket.sendall(message_crypte)
        client_socket.close()
        return



    request_line = request.split(b'\n')[0].decode('utf-8') #On récupère la première ligne de la requête
    method, url, _ = request_line.split() #On récupère la méthode, l'url et le protocole de la requête

    if method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]: #Si la méthode est une méthode classique, on appelle la fonction handle_classic_request
        process_request(client_socket, request)
    elif method == "CONNECT": #Si la méthode est CONNECT, on appelle la fonction handle_connect_methode
        process_connect(client_socket, url)
    else:
        response = b'HTTP/1.1 405 Method Not Allowed\r\n\r\n' #Si la méthode n'est pas supportée, on envoie une erreur 405
        response = our_cryptage.cryptage(response)
        client_socket.sendall(response)
        client_socket.close()


def process_connect(client_socket, url):
    # Fonction qui va gérer la connexion avec le client si la méthode est CONNECT, c'est à dire si le client veut se connecter à un site en https,
    # dans ce cas, on doit maintenir la connexion avec le client et le site distant
    target_host, target_port = url.split(':')  # On récupère l'adresse du site distant et le port
    target_port = int(target_port) # On convertit le port en entier
    print_preffix = "HTTPS_REQUEST" + f"[{target_host}:{target_port}]: "
    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((target_host, target_port))
        client_socket.sendall(our_cryptage.cryptage(b'HTTP/1.1 200 Connection Established\r\n\r\n')) #On envoie une réponse 200 au client pour lui dire que la connexion est établie

        remote_socket.setblocking(0) #On met les sockets en mode non bloquant pour pouvoir les utiliser en même temps
        client_socket.setblocking(0)
        print(print_preffix, "Connexion établie")
        while True:
            try:
                request = client_socket.recv(BUFFER_SIZE) #On récupère les données envoyées par le client (via le proxy d'entrée)
                if not request:
                    break
                #Comme il s'agit deja de requète https, on ne la decrypte pas
                remote_socket.sendall(request) #On envoie les données au site distant
            except socket.error:
                pass

            try:
                response = remote_socket.recv(BUFFER_SIZE) #On récupère les données envoyées par le site distant
                if not response:
                    break
                #Comme il s'agit deja de requète https, on ne la crypte pas
                client_socket.sendall(response) #On envoie les données au client (via le proxy d'entrée)
            except socket.error as e:
                pass

    except Exception as e:
        print(print_preffix, "Erreur lors de la connexion: {e}")

    finally:
        client_socket.close() #On ferme les sockets
        remote_socket.close()

def process_request(client_socket, request):
    request_line = request.split(b'\n')[0].decode('utf-8') #On récupère la première ligne de la requête (deja decrypter dans la fonction handle_client)
    method, url, _ = request_line.split() #On récupère la méthode, l'url et le protocole de la requête
    print_prefix = "HTTP_REQUEST" + f"[{method} {url}] : "
    url_data = url.split('/', 3)  # On récupère l'adresse du site distant et le chemin de la ressource demandée(3 pour ne pas avoir de / en trop, si l'url est http://www.google.fr, on aura ['http:','', 'www.google.fr', ''])
    if len(url_data) < 4: #Si l'url n'est pas correcte, on envoie une erreur 400 au client (via le proxy d'entrée)
        print(print_prefix, ": url invalide")
        client_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
        client_socket.close()
        return

    target_host = url_data[2] #On récupère l'adresse du site distant
    target_url = '/' + url_data[3] #On récupère le chemin de la ressource demandée

    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        target_socket.connect((target_host, 80)) #On se connecte au site distant sur le port 80
    except Exception as e:
        print(print_prefix, "Erreur lors de la connexion: ", e )
        client_socket.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
        client_socket.close()
        return

    target_socket.sendall(request) #On envoie la requête au site distant

    response = b''
    while True:
        data = target_socket.recv(BUFFER_SIZE) #On récupère la réponse du site distant,
        response += data
        if len(data) < BUFFER_SIZE: #Si la taille des données est inférieure à la taille du buffer, on a reçu toute la réponse
            break

    response = our_cryptage.cryptage(response) #On crypte la réponse
    client_socket.sendall(response)
    print(print_prefix, "Reponse envoyée au client")
    client_socket.close()
    target_socket.close()

def handle_start_secure_session_request(client_socket):
    # Cette fonction doit etablir une communication securisé avec le proxy d'entrée
    print_preffix = "INIT_SECUR_SESS: "

    if our_cryptage.getConnectionState() == 1:
        print(print_preffix, "Une connexion securisé est deja en cours d'établissement")
        client_socket.close()
        return
    previous_state = our_cryptage.getConnectionState()
    our_cryptage.setConnectionState(1)

    #On demande à l'utilisateur si il est d'accord pour établir la connexion securisé (max 28 secondes)
    print(print_preffix, "Demande d'établissement d'une connexion securisé recu de:", client_socket.getpeername())
    print(print_preffix, "Voulez vous accepter la demande de connexion securisé ? (y/n)")
    start_time = time.time()
    while True:
        answer = input()
        if answer == "y":
            print(print_preffix, "Lancement de l'échange des clés")
            break
        # si l'utilisateur refuse la connexion securisé ou time > 30s, on envoie un message au proxy d'entrée pour lui dire que l'on refuse
        elif answer == "n" or time.time() - start_time > 28:
            print(print_preffix, "Refus de la demande de connexion securisé")
            our_cryptage.setConnectionState(previous_state)
            client_socket.close()
            return
        else:
            print(print_preffix, "Veuillez entrer y ou n")

    # On envoie un message (non crypté) "READY" au proxy d'entrée pour lui dire qu'on a bien recus ca demande et que l'on est pret
    print(print_preffix, "Envoie de l'accord pour commencer l'échange des clés")
    message_a_envoyer = "READY".encode('utf-8')
    client_socket.sendall(message_a_envoyer)

    # Attendre de recevoir un message du proxy d'entrée qui contient ça clé publique
    print(print_preffix, "Attente de la clé public du proxy d'entrée")
    client_socket.settimeout(10) # On attend 10 secondes max
    publicKey_message = b''
    try:
        while True:
            buf = client_socket.recv(BUFFER_SIZE)
            publicKey_message += buf  # On récupère le message
            if len(buf) < BUFFER_SIZE:
                break

    except socket.timeout:
        print(print_preffix, "Timeout sur l'attente de la clé publique du proxy d'entrée")
        client_socket.close()
        our_cryptage.setConnectionState(0)
        return

    print(print_preffix, "Clé publique recus")

    public = RSA.importKey(publicKey_message)

    #On genere la cle symetrique si besoin
    symetric_key = our_cryptage.getSymetricKey()
    if symetric_key == None:
        print(print_preffix, "Génération d'une nouvelle clé symétrique")
        symetric_key = our_cryptage.getNewSymetricKey()
        our_cryptage.setSymetricKey(symetric_key)

    # On encode la clé symétrique avec la clé publique du proxy d'entrée
    symetric_crypt = our_cryptage.encryptRSA(public, symetric_key)

    #On envoie la clé symetrique(crypté) au proxy d'entrée
    print(print_preffix,"Envoie de la clé symétrique crypté")
    client_socket.sendall(symetric_crypt)

    #On attend de recevoir un message que l'on decrypte avec la clé symetrique (le message doit être "OK")
    client_socket.settimeout(10)
    print(print_preffix,"Attente de la confirmation du proxy d'entrée")
    try:
        message_recu = b''
        while True:
            buf = client_socket.recv(BUFFER_SIZE)
            message_recu += buf
            if len(buf) < BUFFER_SIZE:
                break
    except socket.timeout:
        print(print_preffix, "Timeout sur l'attente de la confirmation du proxy d'entrée")
        client_socket.close()
        our_cryptage.setConnectionState(0)
        return

    message_recu = our_cryptage.decryptage(message_recu)
    print(print_preffix, "Confirmation recus (decrypté): ", message_recu)
    if message_recu != b'OK':
        print(print_preffix, "Erreur de confirmation, message non conforme")
        client_socket.close()
        our_cryptage.setConnectionState(0)
        return

    our_cryptage.setConnectionState(2)
    # On envoie un message au proxy d'entrée "OK" pour lui dire que la connexion est établie en le chiffrant avec la clé symetrique
    message = "OK".encode('utf-8')
    message = our_cryptage.cryptage(message)
    client_socket.sendall(message)
    print(print_preffix, "Connexion securisé établie")
    client_socket.close()
    return

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

