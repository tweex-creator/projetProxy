import socket
import threading
import ssl

# Configuration du proxy visible localement
proxy_host_local = '192.168.1.87'  # Adresse IP du proxy que l'on fait tourner dans se programme
proxy_host_distant = '127.0.0.1'  # Adresse IP du proxy au quel on se connecte

proxy_port_local_for_cli = 12345  # Port du proxy pour le client
proxy_port_local_for_dist = 26667  # Port du proxy pour le proxy distant

proxy_port_dist = 26668  # Port au quel se connecter sur le proxy distant


def main():
    # Initialisation de la socket du proxy local
    input_local_for_cli_proxy_socketl = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #gère les requètes en provenance du client
    input_local_for_dist_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #gère les requètes en provenance du proxy distant

    input_local_for_cli_proxy_socketl.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
    input_local_for_dist_proxy_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)

    input_local_for_cli_proxy_socketl.bind((proxy_host_local, proxy_port_local_for_cli))
    input_local_for_dist_proxy_socket.bind((proxy_host_local, proxy_port_local_for_dist))

    input_local_for_cli_proxy_socketl.listen(50)
    input_local_for_dist_proxy_socket.listen(50)

    input_local_for_cli_proxy_socketl.setblocking(0) #On definie les socket comme non bloquant pour la suite du rpogramme
    input_local_for_dist_proxy_socket.setblocking(0)

    while True:
        try:
            conn, addr = input_local_for_cli_proxy_socketl.accept()
            thread = threading.Thread(target=handle_input_from_user, args=(conn, addr))
            thread.start()
        except socket.error:
            pass

        try:
            conn, addr = input_local_for_dist_proxy_socket.accept()
            # Connexion acceptée
            thread = threading.Thread(target=handle_input_from_distantProxy, args=(conn, addr))
            thread.start()
        except socket.error:
            pass



def handle_input_from_distantProxy(conn, addr):
    raw_data = b''
    while True:
        d = conn.recv(1024)
        raw_data += d
        if not d or len(d) < 1024:
            break

    data = raw_data.decode()
    #print("data: " + data)

    #On decrypte le message
    url_port = data.split()[1]  # on récupère l'URL dans la requête

    url = url_port.split(":")[0]
    port = url_port.split(":")[1]
    debug = True
    if(url.split("/")[0] == "www.example.com" or url.split("/")[0] == "www.google.fr"):
        debug = True

    if debug:
        print(f"New connection from distant proxy {addr}")
        print("url: " + url.split("/")[0] + ", port: " + str(port))

    outputSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    outputSocket.setblocking(1)

    # définir l'adresse IP et le port du serveur distant
    server_address = (url.split("/")[0], int(port))

    # se connecter au serveur
    outputSocket.connect(server_address)
    outputSocket.sendall(data.encode('utf-8'))

    requestDone = False
    while(requestDone == False):
        try:
            d = b''
            while d == '':
                d = outputSocket.recv(1024)

            response = d
            while True:
                d = outputSocket.recv(1024)
                response += d
                if not d or len(d) < 1024:
                    break
            if debug:
                print("client : " + data)
                print("server respons: " + response.decode('utf-8'))
            # On crypte la réponse
            conn.sendall(response)  # on renvoie la réponse
            requestDone = True
        except socket.error as e:
            if debug:
                print(f'Error occurred: {str(e)}')
            pass

    outputSocket.close()


def handle_input_from_user(conn, addr):
    conn.setblocking(1)

    #print(f"New connection from user {addr}")

    #Recuperation de la requete du client
    request = b''
    while True:
        d = conn.recv(1024)
        request += d
        if not d or len(d) < 1024:
            break

    #conn.sendall("HTTP/1.1 200 OK".encode())

    #Modification de la requètre (cryptage)
    data = request.decode()
    # print("data: " + data)

    # On decrypte le message
    url_port = data.split()[1]  # on récupère l'URL dans la requête

    url = url_port.split(":")[0]
    port = url_port.split(":")[1]
    debug = False
    if (url.split("/")[0] == "www.example.com" or url.split("/")[0] == "www.google.fr"):
        debug = True

    if debug:
        print(f"New connection from distant proxy {addr}")
        print("url: " + url.split("/")[0] + ", port: " + str(port))
        print("req: " + request.decode())

    outputSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # définir l'adresse IP et le port du serveur distant
    server_address = (url.split("/")[0], int(port))

    # se connecter au serveur
    outputSocket.connect(server_address)
    outputSocket = ssl.wrap_socket(outputSocket,ssl_version=ssl.PROTOCOL_TLS)

    outputSocket.sendall(data.encode('utf-8'))

    try:
        d = b''
        response = d
        while True:
            d = outputSocket.recv(1024)
            response += d
            if not d or len(d) < 1024:
                break
        if debug:
            print("client : " + data)
            print("server respons: " + response.decode('utf-8'))
        # On crypte la réponse
        conn.sendall(response)  # on renvoie la réponse
    except socket.error as e:
        if debug:
            print(f'Error occurred: {str(e)}')
            pass

    outputSocket.close()
    conn.close()

    return
    # Initialisation de la socket pour communiquer avec le proxy distant
    distant_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    distant_proxy_socket.connect((proxy_host_distant, proxy_port_dist))
    # Envoie de la requète au proxy distant
    distant_proxy_socket.sendall(request)
    raw_data = b''
    while True:
        d = distant_proxy_socket.recv(1024)
        if not d or len(d) < 1024:
            break
        raw_data += d
    #Modification de la reponse (decryptage)
    # Envoie de la réponse au client
    conn.sendall(raw_data)
    print("send To client :" + raw_data.decode())
    distant_proxy_socket.close()
    conn.close()


if __name__ == '__main__':
    main()
