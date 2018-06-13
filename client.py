from cryptoran import BlockCiphers
import socket
import pickle
import threading
import sys
from EspionageConnection import EspionageConnection

class EspionageClient(EspionageConnection):
    def __init__(self, cipher: BlockCiphers.BlockCipher, 
        serverIP: str, serverPort: int, messageHandler):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((serverIP, serverPort))
        self.bufferSize = 1024
        self.listenerThread = None
        self.connectionAlive = True
        super().__init__(cipher, serverIP, serverPort, messageHandler)

    def listen(self):
        while self.connectionAlive:
            try:
                payload = self.sock.recv(self.bufferSize)
                if not payload:
                    raise Exception()
                else:
                    self.messageHandler(self.decodeReceived(payload))
            except:
                print('Disconnected from server')
                self.connectionAlive = False

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
    cipher = BlockCiphers.AES('cbc', 123456789, 987654321)
    client = EspionageClient(cipher, '127.0.0.1', 5005, print)
    client.start()
    print('Input ".exit" to terminate the program')
    while client.isConnected():
        message = input('>>')
        if message == '.exit':
            print('Terminating connection')
            client.stop()
            print('Connection terminated by user')
            break
        client.send(message)
    
    print('Terminating program')