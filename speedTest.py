import time
import urllib.request

from numpy import char

import our_cryptage


def speedTest(url):
    moyenne = 0
    for i in range(0, 10):
        start = time.time()
        urllib.request.urlopen(url)
        end = time.time()
        print(end - start)
        moyenne += end - start

    print("Moyenne " + url + " : ", moyenne / 10)


def cryptageSpeedTest():
    # Donne le temps nescessaire pour crypter des messages de 10, 100, 1000 et 10000 caractères
    our_cryptage.setConnectionState(2)
    our_cryptage.setSymetricKey(our_cryptage.getNewSymetricKey())

    alphabet = "abcdefghijklmnopqrstuvwxyz"
    base = 10000000
    message = ""
    for j in range(0, base):
        message += alphabet[j % 26]

    for i in range(1, 50):
        message_loc = ""
        for j in range(0, i):
            message_loc += message

        message_loc = message_loc.encode()
        start = time.time()
        res = our_cryptage.cryptage(message_loc)
        end = time.time()
        time_crypt  =
        print("Temps pour crypter un message de " + str(len(message_loc)) + " (" + str(len(res)) + ") caractères : ", (end - start) * 1000, " milli secondes")
        start = time.time()
        res = our_cryptage.decryptage(res)
        end = time.time()
        print("Temps pour décrypter un message de " + str(len(res)) + " (" + str(len(res)) + ") caractères : ", (end - start) * 1000, " milli secondes")
        print("")
        #Export les resultat dans excel


cryptageSpeedTest()
