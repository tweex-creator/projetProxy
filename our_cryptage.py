import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#SYMETRIC_KEY = None #La clé de cryptage/décryptage symetrique
SYMETRIC_KEY = b'1234567890123456' #La clé de cryptage/décryptage symetrique
CONNECTION_STATE = 0 #0: Pas de connexion securisé, 1: En cours d'établissement, 2: Connexion securisé etablie
def cryptage(byte_message): #TODO: Herve
    #Fonction qui va crypter le message avec la clé symetrique
    #si les clé symetrique n'est pas initialisée(il faut demarer une session securiser), on retourne none
    if getSymetricKey() == None or CONNECTION_STATE == 0:
        print("Clé symetrique ou connexion non initialisée")
        return None
    else:
        #On crypte le message avec la clé symetrique
        #On retourne le message crypté
        encrypter = AES.new(getSymetricKey(), AES.MODE_CBC)
        message_encrypte = encrypter.iv + encrypter.encrypt(pad(byte_message, AES.block_size))
        return message_encrypte

def decryptage(byte_encrypted_message): #TODO: Herve
    #Fonction qui va décrypter le message avec la clé symetrique
    #si la clé symetrique n'est pas initialisée, on retourne None
    if getSymetricKey() == None or CONNECTION_STATE == 0:
        return None
    else:
        #On décrypte le message avec la clé symetrique
        #On retourne le message décrypté
        try:
            decrypter = AES.new(getSymetricKey(), AES.MODE_CBC, byte_encrypted_message[:16])
            message_decrypte = unpad(decrypter.decrypt(byte_encrypted_message[16:]), AES.block_size)
            #print ("Message décrypté: ", message_decrypte)
            return message_decrypte
        except ValueError as e:
            #Si le message n'a pas pu être décrypté, affiche l'erreur
            return b"error"

def getNewSymetricKey(): #TODO: Herve
    #Fonction qui va générer une clé symetrique
    #Les clés fournit seront differentes à chaque execution
    #ATTENTION, c'est à la fonction appelante de definir la clé symetrique comme étant la clé symetrique globale (variable SYMETRIC_KEY)
    SymetricKey = get_random_bytes(16) #On genere une clé symetrique de 16 octets soit 16*8 = 128 bits
    return SymetricKey

def setSymetricKey(key): #TODO: Herve
    #On ne manipule pas directement la variable SYMETRIC_KEY pour pouvoir par la suite utiliser un moyen plus sécurisé de stockage de la clé symetrique
    #Fonction qui va définir la clé symetrique comme étant la clé symetrique globale (variable SYMETRIC_KEY)
    global SYMETRIC_KEY
    SYMETRIC_KEY = key
    return True

def getSymetricKey(): #TODO: Herve
    #On ne manipule pas directement la variable SYMETRIC_KEY pour pouvoir par la suite utiliser un moyen plus sécurisé de stockage de la clé symetrique
    #Fonction qui va retourner la clé symetrique globale (variable SYMETRIC_KEY)
    global SYMETRIC_KEY
    if CONNECTION_STATE == 0:
        return None
    return SYMETRIC_KEY

def getNewPublicAndPrivateKeyPair(): #TODO: Zaide
    # Générer une clé RSA de 2048 bits
    key = RSA.generate(2048)
    PrivateKey = key.export_key()  # La clé privée
    PublicKey = key.publickey().export_key()  # La clé publique

    # Fonction qui va générer une clé privée et publique
    # Les clés fournit seront differentes à chaque execution


    return key, PrivateKey, PublicKey
def decryptRSA(privateKey, message):
    #Fonction qui va décrypter le message avec la clé privée
    decryptor = PKCS1_OAEP.new(privateKey)
    decrypted_message = decryptor.decrypt(message)
    return decrypted_message

def encryptRSA(publicKey, message):
    # Fonction qui va crypter le message avec la clé publique
    cryptor = PKCS1_OAEP.new(publicKey)
    encrypted_message = cryptor.encrypt(message)

    return encrypted_message
def setConnectionState(state):
    #Fonction qui va definir l'etat de la connexion
    #0: Pas de connexion securisé, 1: En cours d'établissement, 2: Connexion securisé etablie
    global CONNECTION_STATE
    CONNECTION_STATE = state
    return True

def getConnectionState():
    #Fonction qui va retourner l'etat de la connexion
    #0: Pas de connexion securisé, 1: En cours d'établissement, 2: Connexion securisé etablie
    global CONNECTION_STATE
    return CONNECTION_STATE