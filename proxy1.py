import socket
import threading
import time

import our_cryptage


# Configuration Proxy
PROXY_IP = '0.0.0.0' #L'ip de notre proxy, ici '0.0.0.0' veut dire que le proxy est accessible depuis n'importe quelle interface réseau de la machine
PROXY_PORT = 12343 #Le port sur lequel le proxy va écouter
BUFFER_SIZE = 4096 #Taille du buffer de réception
PROXY_OUTPUT_IP = 'localhost' #L'ip de la machine sur laquelle tourne le proxy de sortie
PROXY_OUTPUT_PORT = 12345 #Le port sur lequel le proxy de sortie écoute

def handle_client(client_socket, client_addr): #Fonction qui va gérer la connexion initiale avec le client
    #On commence par recuperer la requète du client(dans son integralité même si elle est plus grande que le buffer)
    request = b''
    while True:
        data = client_socket.recv(BUFFER_SIZE) #On récupère la requête du client
        request += data
        if len(data) < BUFFER_SIZE: #Si la taille de la requête est inférieure à la taille du buffer, on a reçu toute la requête
            break

    #On recupère la première ligne qui vas nous permettre de savoir si il s'agit d'une simple requette http ou d'une requette de connexion sécurisée (https)
    request_line = request.split(b'\n')[0].decode('utf-8') #On récupère la première ligne de la requête
    method, url, _ = request_line.split() #On récupère la méthode, l'url et le protocole de la requête
    if method == "CONNECT": #Si la méthode est CONNECT, on appelle la fonction handle_connect_methode qui vas permettre de mettre en place une connexion sécurisée
        handle_connect_methode(client_socket, url, request)
    else: #Sinon, on appelle la fonction handle_classic_request qui vas simplement recuperer l'information, la renvoyer au client puis fermer la connexion
        handle_classic_request(client_socket, url, request)

def check_if_secure_connection_open():
    # Fonction qui va vérifier si une connexion sécurisée est déjà ouverte avec le proxy distant (si l'echange d'une clé symétrique a déjà eu lieu)
    # Si c'est le cas, on retourne true, sinon on retourne false
    if our_cryptage.getConnectionState() != 2:
        print("Connexion sécurisée non ouverte")
        return False #Si la connection securisé n'est pas ouverte, on retourne false

    message = "Ping" #On envoie un message au proxy distant pour vérifier si la connexion est toujours ouverte et la clé symétrique toujours valide
    message = message.encode('utf-8')
    message_crypte = our_cryptage.cryptage(message) #On crypte le message avec la clé symétrique en notre possession
    output_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    output_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT))
    output_socket.sendall(message_crypte) #On envoie le message crypté au proxy distant
    try:
        output_socket.settimeout(10) #On attend 10 secondes max pour recevoir une réponse du proxy distant
        response = output_socket.recv(BUFFER_SIZE)
        response = our_cryptage.decryptage(response) #On décrypte la réponse
        if response == b"Pong": #Si la réponse est bien "Pong", alors la connexion est toujours ouverte et le proxy distant a bien pu dechiffrer le message donc la clé symétrique est toujours valide
            return True
        else:   #Sinon, la connexion n'est pas ouverte
            print("Erreur: la connexion sécurisée n'est pas/plus ouverte")
            return False

    except socket.error:
        print("Erreur: Le proxy distant n'a pas répondu (timeout = 10s)")
        return False



def handle_connect_methode(client_socket, url, request):
    # Fonction qui va gérer la connexion avec le client si la méthode est CONNECT, c'est à dire si le client veut se connecter à un site en https (donc avec un certificat ssl)
    # Dans ce cas là, on vas maintenir la connexion aves le proxy distant ouverte tout au long de l'echaange entre le client et le serveur distant

    output_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    output_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT)) #On se connecte au proxy de sortie

    #On verifie que la connexion securisé est toujours ouverte(si elle ne l'ai pas on la réouvre)
    # On verifie que la connexion securisé est toujours ouverte(si elle ne l'ai pas on la réouvre)
    if check_if_secure_connection_open() == False:
        print("Ouverture d'une nouvelle connexion sécurisée")
        if not start_secure_session():  # On ouvre une connexion sécurisée avec le proxy distant
            print("Erreur: la connexion sécurisée n'a pas pu être établie, abandon du client")
            client_socket.sendall(
                "HTTP/1.1 500 Internal Proxy Error\r\n\r\n".encode('utf-8'))  # On envoie une erreur au client
            client_socket.close()  # On ferme la connexion avec le client et le proxy de sortie
            output_socket.close()
            return

    request = our_cryptage.cryptage(request) #On crypte la requête
    output_socket.sendall(request) #On envoie la requête (crypté) au proxy de sortie

    try:
        output_socket.settimeout(10) #On attend 10 secondes max pour recevoir une réponse du proxy distant
        response = output_socket.recv(BUFFER_SIZE) #On récupère la réponse du proxy de sortie
    except socket.error as e:
        print("Erreur: Le proxy distant n'a pas répondu (timeout = 10s)", e)
        client_socket.sendall("HTTP/1.1 500 Internal Proxy Error\r\n\r\n".encode('utf-8'))
        client_socket.close()
        output_socket.close()
        return

    response = our_cryptage.decryptage(response) #On décrypte la réponse

    if "200 Connection Established" in response.decode('utf-8'): #Si la connexion a été établie avec succès
        print("Tunnel HTTPS établi avec succès pour le site", url)
        client_socket.sendall(response) #On envoie la réponse au client
    else:
        print("Erreur: la connexion sécurisée n'a pas pu être établie")
        client_socket.sendall("HTTP/1.1 500 Internal Proxy Error\r\n\r\n".encode('utf-8')) #On envoie une erreur au client
        client_socket.close() #On ferme la connexion avec le client et le proxy de sortie
        output_socket.close()
        return

    output_socket.setblocking(0) #On met les sockets en mode non bloquants pour pouvoir gerer les deux sockets en même temps
    client_socket.setblocking(0)

    while True:
        #On récupère la requête du client et on l'envoie au proxy de sortie (si il y en a une)
        try:
            request = client_socket.recv(BUFFER_SIZE) #On récupère la requête du client
            if not request: #Si la requête est vide, on ferme la connexion
                output_socket.sendall(''.encode('utf-8'))
                client_socket.close()
                output_socket.close()
                return
            #Comme il s'agit deja d'une connexion sécurisé, on ne crypte pas la requête
            output_socket.sendall(request) #On envoie la requête au proxy de sortie
        except socket.error:
            #Si on a une erreur, il se peut que ce soit parce que le client n'a pas encore envoyé de requête, donc on passe
            pass

        #On récupère la réponse du proxy de sortie et on l'envoie au client (si il y en a une)
        try:
            response = output_socket.recv(BUFFER_SIZE) #On récupère la réponse du proxy de sortie
            if not response: #Si la réponse est vide, on ne fait rien
                break
            #Comme il s'agit deja d'une connexion sécurisé, on ne décrypte pas la réponse
            client_socket.sendall(response) #On envoie la réponse au client
        except socket.error:
            #Si on a une erreur, il se peut que ce soit parce que le proxy de sortie n'a pas encore envoyé de réponse, donc on passe
            pass

    client_socket.close() #On ferme la connexion avec le client et le proxy de sortie
    output_socket.close()

def handle_classic_request(client_socket, url, request):
    # Fonction qui va gérer la connexion avec le client si la méthode n'est pas CONNECT, c'est à dire si le client veut se connecter à un site en http
    output_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #On se connecte au proxy de sortie
    output_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT))

    #On verifie que la connexion securisé est toujours ouverte(si elle ne l'ai pas on la réouvre)
    if check_if_secure_connection_open() == False:
        print("Ouverture d'une nouvelle connexion sécurisée")
        if not start_secure_session(): #On ouvre une connexion sécurisée avec le proxy distant
            print("Erreur: la connexion sécurisée n'a pas pu être établie")
            client_socket.sendall("HTTP/1.1 500 Internal Proxy Error\r\n\r\n".encode('utf-8')) #On envoie une erreur au client
            client_socket.close() #On ferme la connexion avec le client et le proxy de sortie
            output_socket.close()
            return

    request = our_cryptage.cryptage(request) #On crypte la requête
    output_socket.sendall(request) #On envoie la requête au proxy de sortie
    response = b''
    while True:
        data = output_socket.recv(BUFFER_SIZE)
        response += data
        if len(data) < BUFFER_SIZE:
            break

    response = our_cryptage.decryptage(response) #On décrypte la réponse
    client_socket.sendall(response) #On envoie la réponse au client
    print("Demande de connexion au site", url, "traitée avec succès")
    client_socket.close()
    output_socket.close()


def start_secure_session(): #TODO: Zaïde
    #Fonction qui va démarrer une session sécurisée avec le proxy de sortie
    #On verifie que l'echange de clés n'est pas déjà en cours
    if our_cryptage.getConnectionState() == 1: #Si l'echange de clés est déjà en cours, on attend qu'il soit finit (il a pus être lancé dans un autre thread)
        while our_cryptage.getConnectionState() == 1: #Si l'echange de clés est déjà en cours,
            time.sleep(1)
        if our_cryptage.getConnectionState() == 2: #Si l'echange de clés a réussi, on ne fait rien sinon on relance l'echange de clés
            return

    #On lance l'echange de clés
    our_cryptage.setConnectionState(1) #On indique que l'echange de clés est en cours

    #TODO: On envoie un message (non crypté) au proxy de sortie "START_SECURE_SESSION"
    #TODO: On attend de recevoir un message du proxy de sortie "READY"
    #TODO: On genère notre clé privée et publique pour le proxy d'entrée qui vas permettre d'echanger la clé symetrique de facons securisé
    #TODO: On envoie notre clé publique au proxy de sortie
    #TODO: On attend de recevoir la clé symetrique founrit par le proxy de sortie (cryptée que l'on doit decrypter avec notre clé privée)
    #TODO: On decrypte la clé symetrique avec notre clé privée
    #TODO: On envoie un message au proxy de sortie "OK" (crypté avec la clé symétrique)
    #TODO: On attend de recevoir un message du proxy de sortie
    #TODO: On decrypte le message avec la clé symétriquea
    #TODO: Si le message est "OK", on retourne True
    #TODO: Sinon, on retourne False

    success = True #temporaire
    if success: #A modifier
        our_cryptage.setConnectionState(2) #On indique que l'echange de clés est finit et qu'il a réussi
        return True
    else:
        our_cryptage.setConnectionState(0) #On indique que l'echange de clés est finit et qu'il a échoué
        return False




def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((PROXY_IP, PROXY_PORT))
    server.listen(50)
    print(f"Proxy d'entrée en écoute sur {PROXY_IP}:{PROXY_PORT}")

    while True:
        client_socket, client_addr = server.accept()
        #print(f"Requête reçue de {client_addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_addr))
        client_handler.start()

if __name__ == '__main__':
    main()
