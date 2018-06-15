from cryptoran import BlockCiphers, SecretKeySharing
import socket
import select
import threading
import sys, os
from EspionageConnection import EspionageConnection

class EspionageClient(EspionageConnection):
    def __init__(self, cipher: BlockCiphers, serverIP: str, 
            serverPort: int, messageHandler, disconnectionHandler: callable, cipherIV):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((serverIP, serverPort))
        self.bufferSize = 1024
        self.connectionAlive = True
        self.disconnectionHandler = disconnectionHandler
        self.printLock = threading.Lock()

        self.dh = None
        self.cipherClass = cipher
        self.cipher = None
        self.iv = cipherIV

        super().__init__(serverIP, serverPort, messageHandler)

    def listen(self):
        # 1 - set common secret key with server
        dhRaw = self.sock.recv(1024)
        dhInfo = self.decodeUnencrypted(dhRaw)
        self.dh = SecretKeySharing.DiffieHellman(dhInfo[0], dhInfo[1])
        _, _, expSecret = self.dh.generateSecret()

        self.sendUnencrypted(expSecret, self.sock)

        cipherKey = self.dh.generateSharedKey(dhInfo[2])
        self.cipher = self.cipherClass('cbc', cipherKey, self.iv)

        while self.connectionAlive:
            try:
                readable, _, _ = select.select([self.sock], [], [], 0.1)
                for _ in readable:
                    payload = self.sock.recv(self.bufferSize)
                    if not payload:
                        raise Exception()
                    else:
                        with self.printLock:
                            self.messageHandler(self.decodeReceived(payload, self.cipher))
            except:
                self.connectionAlive = False
                self.disconnectionHandler()
                break

    def start(self):
        threading.Thread(target=self.listen).start()

    def stop(self):
        self.connectionAlive = False
        self.sock.close()

    def send(self, message):
        self.sendMessage(message, (self.sock, self.cipher))

    def isConnected(self):
        return self.connectionAlive

if __name__ == '__main__':
    aesiv = 0xed7ef412977a7df3af9e67307bd2214b
    ip, port = None, None
    userTermination = False

    try:
        ip = sys.argv[1]
        port = int(sys.argv[2])
    except:
        print('usage: python client.py ip port')
        os._exit(1)
    
    def disconnectionHandler():
        print('disconnected from server!')
        os._exit(1)
    
    def connectionHandler(message: str):
        print(f'Server: {message}')

    client = EspionageClient(BlockCiphers.AES, ip, port, print, disconnectionHandler, aesiv)
    client.start()
    print('Connected to server\nInput ".exit" to terminate the program')
    
    while client.isConnected():
        message = input()
        if message == '.exit':
            userTermination = True
            print('Terminating connection')
            client.stop()
            break
        client.send(message)