import time
import urllib.request

moyenne = 0
for i in range(0, 10):
    start = time.time()
    urllib.request.urlopen("http://httpforever.com/")
    end = time.time()
    print(end - start)
    moyenne += end - start

print("Moyenne: ", moyenne/10)

