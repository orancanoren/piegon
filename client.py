from cryptoran import BlockCiphers
import socket
import select
import threading
import sys, os
from EspionageConnection import EspionageConnection

class EspionageClient(EspionageConnection):
    def __init__(self, cipher: BlockCiphers.BlockCipher, 
        serverIP: str, serverPort: int, messageHandler, disconnectionHandler: callable):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((serverIP, serverPort))
        self.bufferSize = 1024
        self.connectionAlive = True
        self.disconnectionHandler = disconnectionHandler
        super().__init__(cipher, serverIP, serverPort, messageHandler)

    def listen(self):
        while self.connectionAlive:
            try:
                readable, _, _ = select.select([self.sock], [], [], 0.1)
                for _ in readable:
                    payload = self.sock.recv(self.bufferSize)
                    if not payload:
                        raise Exception()
                    else:
                        self.messageHandler(self.decodeReceived(payload))
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
        self.sendMessage(message, self.sock)

    def isConnected(self):
        return self.connectionAlive

if __name__ == '__main__':
    userTermination = False
    def disconnectionHandler():
        print('disconnected from server!')
        os._exit(1)

    cipher = BlockCiphers.AES('cbc', 12345678910, 10987654321)
    client = EspionageClient(cipher, '127.0.0.1', 5005, print, disconnectionHandler)
    client.start()
    print('Connected to server\nInput ".exit" to terminate the program')
    
    while client.isConnected():
        message = input('>>')
        if message == '.exit':
            userTermination = True
            print('Terminating connection')
            client.stop()
            break
        client.send(message)