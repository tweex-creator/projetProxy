import our_cryptage

#Test des fonctions setSymetricKey() et getNewSymetricKey()
print("Test de la fonction setSymetricKey()")
key = our_cryptage.getNewSymetricKey()
print("Clé symetrique générée: " + str(key))
our_cryptage.setSymetricKey(key)
print("Clé symetrique définie: " + str(our_cryptage.getSymetricKey()))

#Test de la fonction cryptage()
print("Test de la fonction cryptage()")
message = "Bonjour, je suis un message crypté"
message = message.encode('utf-8')
print("Message à crypter: " + message.decode('utf-8'))
message_crypte = our_cryptage.cryptage(message)
print("Message crypté: " + str(message_crypte))

#Test de la fonction decryptage()
print("Test de la fonction decryptage()")
message_decrypte = our_cryptage.decryptage(message_crypte)
print("Message décrypté: " + message_decrypte.decode('utf-8'))




