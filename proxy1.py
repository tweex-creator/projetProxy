import socket
import threading
import time

import our_cryptage

# Configuration Proxy
PROXY_IP = '0.0.0.0' #L'ip de notre proxy, ici '0.0.0.0' veut dire que le proxy est accessible depuis n'importe quelle interface réseau de la machine
PROXY_PORT = 12344 #Le port sur lequel le proxy va écouter
BUFFER_SIZE = 4096 #Taille du buffer de réception
PROXY_OUTPUT_IP = 'localhost' #L'ip de la machine sur laquelle tourne le proxy de sortie
PROXY_OUTPUT_PORT = 12345 #Le port sur lequel le proxy de sortie écoute

def handle_client(client_socket): #Fonction qui va gérer la connexion initiale avec le client
    #On commence par recuperer la requète du client(dans son integralité même si elle est plus grande que le buffer)
    print_preffix = "HANDLE_CLI: "
    request = b''
    while True:
        data = client_socket.recv(BUFFER_SIZE) #On récupère la requête du client
        request += data
        if len(data) < BUFFER_SIZE: #Si la taille de la requête est inférieure à la taille du buffer, on a reçu toute la requête
            break

    #On recupère la première ligne qui vas nous permettre de savoir si il s'agit d'une simple requette http ou d'une requette de connexion sécurisée (https)
    request_line = request.split(b'\n')[0].decode('utf-8') #On récupère la première ligne de la requête
    method, url, _ = request_line.split() #On récupère la méthode, l'url et le protocole de la requête

    if not check_if_secure_connection_open():
        if not start_secure_session():
            print(print_preffix, "La connexion sécurisée n'a pas pu être établie, abandon du client")
            client_socket.sendall("HTTP/1.1 502 Internal Proxy Error\r\n\r\n".encode('utf-8'))
            client_socket.close()
            return

    if method == "CONNECT": #Si la méthode est CONNECT, on appelle la fonction handle_connect_methode qui vas permettre de mettre en place un tunnel sécurisé
        handle_connect_methode(client_socket, url, request)
    else: #Sinon, on appelle la fonction handle_classic_request qui vas simplement recuperer l'information, la renvoyer au client puis fermer la connexion
        handle_classic_request(client_socket, url, request)

def check_if_secure_connection_open():
    # Fonction qui va vérifier si une connexion sécurisée est déjà ouverte avec le proxy distant (si l'echange d'une clé symétrique a déjà eu lieu)
    # Si c'est le cas, on retourne true, sinon on retourne false
    print_prefix = "CHECK_SECUR_SESS: "
    if our_cryptage.getConnectionState() != 2:
        print(print_prefix, "Connexion sécurisée non ouverte (state != 2)")
        return False #Si la connection securisé n'est pas ouverte, on retourne false
    message = "Ping" #On envoie un message au proxy distant pour vérifier si la connexion est toujours ouverte et la clé symétrique toujours valide
    message = message.encode('utf-8')
    message_crypte = our_cryptage.cryptage(message) #On crypte le message avec la clé symétrique en notre possession
    output_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        output_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT))
    except socket.error:
        print(print_prefix, "Erreur: le proxy distant n'est pas joignable")
        return False

    output_socket.sendall(message_crypte) #On envoie le message crypté au proxy distant
    try:
        output_socket.settimeout(30) #On attend 60 secondes max pour recevoir une réponse du proxy distant
        response = output_socket.recv(BUFFER_SIZE)
        response = our_cryptage.decryptage(response) #On décrypte la réponse
        if response == b"Pong": #Si la réponse est bien "Pong", alors la connexion est toujours ouverte et le proxy distant a bien pu dechiffrer le message donc la clé symétrique est toujours valide
            #print(print_prefix, "La connexion sécurisée est toujours ouverte (ping OK)")
            return True
        else:   #Sinon, la connexion n'est pas ouverte
            print(print_prefix, "La connexion sécurisée n'est pas/plus ouverte (pas ou mauvaise réponse au ping)")
            return False

    except socket.error:
        print(print_prefix, "Le proxy distant n'a pas répondu (timeout = 10s)")
        return False

def handle_connect_methode(client_socket, url, request):
    # Fonction qui va gérer la connexion avec le client si la méthode est CONNECT, c'est à dire si le client veut se connecter à un site en https (donc avec un certificat ssl)
    # Dans ce cas là, on vas maintenir la connexion aves le proxy distant ouverte tout au long de l'echaange entre le client et le serveur distant
    # On vas donc créer un tunnel sécurisé entre le client et le serveur distant
    print_prefix = "HANDLE_CONNECT: "
    output_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    output_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT)) #On se connecte au proxy de sortie

    request = our_cryptage.cryptage(request) #On crypte la requête
    output_socket.sendall(request) #On envoie la requête (crypté) au proxy de sortie

    try:
        output_socket.settimeout(10) #On attend 10 secondes max pour recevoir une réponse du proxy distant
        response = output_socket.recv(BUFFER_SIZE) #On récupère la réponse du proxy de sortie
    except socket.error as e:
        print(print_prefix, "Le proxy distant n'a pas répondu (timeout = 10s)")
        client_socket.sendall("HTTP/1.1 502 Internal Proxy Error\r\n\r\n".encode('utf-8'))
        client_socket.close()
        output_socket.close()
        return

    response = our_cryptage.decryptage(response) #On décrypte la réponse

    if "200 Connection Established" in response.decode('utf-8'): #Si la connexion a été établie avec succès
        print(print_prefix, "Tunnel HTTPS établi avec succès pour le site", url)
        client_socket.sendall(response) #On envoie la réponse au client
    else:
        print(print_prefix, "La connexion sécurisée n'a pas pu être établie")
        client_socket.sendall("HTTP/1.1 502 Internal Proxy Error\r\n\r\n".encode('utf-8')) #On envoie une erreur au client
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
                #print(print_prefix, "Connexion fermée par le client")
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
    print_prefix = "HANDLE_HTTP_REQUEST: "
    output_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #On se connecte au proxy de sortie
    output_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT))

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

    print(print_prefix, "Requète pour le site", url, "traitée avec succès")
    client_socket.close()
    output_socket.close()

def start_secure_session():
    # Fonction qui va démarrer une session sécurisée avec le proxy de sortie
    # On vérifie que l'echange de clés n'est pas déjà en cours
    print_preffix = "INIT_SECUR_SESS: "
    if our_cryptage.getConnectionState() == 1:  # Si l'echange de clés est déjà en courson ne fait rien
        print(print_preffix, "Echange de clés déjà en cours")
        return False

    success = False
    old_symetric_key = our_cryptage.getSymetricKey()  # On sauvegarde l'ancienne clé symétrique
    def restore_old_values():
        our_cryptage.setSymetricKey(old_symetric_key)  # On restaure l'ancienne clé symétrique
        our_cryptage.setConnectionState(0)  # On indique que l'echange de clés est terminé et en echec

    # On lance l'echange de clés
    our_cryptage.setConnectionState(1)  # On indique que l'echange de clés est en cours

    print(print_preffix, "Ouverture d'une session securisée...")

    #On ouvre la connexion avec le proxy distant
    try:
        print(print_preffix, "Ouverture d'un socket avec le proxy distant")
        proxy_distant_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_distant_socket.connect((PROXY_OUTPUT_IP, PROXY_OUTPUT_PORT))
    except socket.error:
        print(print_preffix, "La connexion sécurisée n'a pas pu être établie (impossible d'ouvrir un socket avec le proxy distant)")
        restore_old_values()
        return False

    #On envoie un message (non crypté) au proxy de sortie "START_SECURE_SESSION" pour qu'il commence également la procédure d'échange de clés
    print(print_preffix, "Envoie du message START_SECURE_SESSION")
    message_open_secure = "START_SECURE_SESSION"
    message_open_secure = message_open_secure.encode('utf-8')
    proxy_distant_socket.sendall(message_open_secure)

    #On attend de recevoir un message du proxy de sortie "READY" qui indique qu'il est pret a procéder à l'echange de clés
    while True:
        proxy_distant_socket.settimeout(30) #on attend au plus 30 secondes
        try:
            respons = b''
            while True:
                data = proxy_distant_socket.recv(BUFFER_SIZE)
                respons += data
                if len(data) < BUFFER_SIZE:
                    break

            respons = respons.decode('utf-8')  # On récupère la réponse du proxy de sortie

            if respons == 'READY':
                print(print_preffix, "Proxy distant pret pour l'echange de clés")
                break
            else:
                print(print_preffix, "ERREUR: Le proxy a renvoyé une réponse inattendue au lieux de READY (abandon de l'echange de clés):", respons)
                restore_old_values()
                return False

        except socket.error as e:
            print(print_preffix, "ERREUR: Le proxy distant n'a pas répondu (timeout = 10s), abandon de l'etablissement d'une connexion securisée (wait READY)", e)
            restore_old_values()
            return False

    # On genère nos clés privée et publique pour le proxy d'entrée qui vas permettre d'echanger la clé symetrique de facons securisé
    print(print_preffix, "Generation de la clé assymetriques(RSA)")
    key_rsa, private_key_RSA, public_key_RSA = our_cryptage.getNewPublicAndPrivateKeyPair()
    # On envoie notre clé publique au proxy de sortie
    print(print_preffix, "Envoie de la clé publique au proxy distant")
    proxy_distant_socket.sendall(public_key_RSA)  # On envoie la cle public au proxy de sortie

    # On attend de recevoir la clé symetrique founrie par le proxy de sortie (cryptée que l'on doit decrypter avec notre clé privée)
    try:
        symetric_key_respons = b''
        while True:
            data = proxy_distant_socket.recv(BUFFER_SIZE)
            symetric_key_respons += data # On récupère la réponse du proxy de sortie qui doit contenir la clé symetrique
            if len(data) < BUFFER_SIZE:
                break
    except socket.error:
        print(print_preffix, "Erreur: Le proxy distant n'a pas renvoyé la clé symetrique (timeout = 10s), abandon de l'etablissement d'une connexion securisée")
        restore_old_values()
        return False
    print(print_preffix, "Clé symetrique recus, decryptage en cours...")
    #On decrypte la clé symetrique avec notre clé privée
    decrypted_symetric_key = our_cryptage.decryptRSA(key_rsa, symetric_key_respons)
    our_cryptage.setSymetricKey(decrypted_symetric_key)  # On enregistre la clé symetrique dans notre objet cryptage
    print(print_preffix, "Clé symetrique decryptée")

    # On envoie un message au proxy de sortie "OK" (crypté avec la clé symétrique) pour verifier le bon fonctionnement de l'encryption symetrique
    message = "OK"
    message_crypt = our_cryptage.cryptage(message.encode('utf-8'))
    print(print_preffix, "Envoie du message OK (crypté)")
    proxy_distant_socket.sendall(message_crypt)

    # On attend de recevoir un message du proxy de sortie
    print(print_preffix, "Attente de la réponse du proxy de sortie")
    response = b''
    while True:
        response += proxy_distant_socket.recv(BUFFER_SIZE)
        if len(response) < BUFFER_SIZE:
            break
    # On decrypte le message avec la clé symétrique
    message_decrypt = our_cryptage.decryptage(response)
    print(print_preffix,"Réponse du proxy de sortie recus (décrypté):", message_decrypt)
    # Si le message est "OK", on retourne True
    if message_decrypt == b'OK':
        success = True
    # Sinon, on retourne False

    if success:
        print(print_preffix, "Echange de clé réussi")
        our_cryptage.setConnectionState(2)  # On indique que l'echange de clés est finit et qu'il a réussi
        return True
    else:
        print(print_preffix, "Echange de clé échoué")
        restore_old_values()
        return False

def main():
    while not start_secure_session():
        print("Echange de clé échoué, réessai dans 5s")
        time.sleep(5)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((PROXY_IP, PROXY_PORT))
    server.listen(50)
    print(f"Proxy d'entrée en écoute sur {PROXY_IP}:{PROXY_PORT}")

    while True:
        client_socket, client_addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args= (client_socket,) )
        client_handler.start()

if __name__ == '__main__':
    main()
