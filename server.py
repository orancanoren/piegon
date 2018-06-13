from cryptoran import BlockCiphers
from EspionageConnection import EspionageConnection
import pickle
import socket
import threading
import sys
import os
from collections import namedtuple


class EspionageServer(EspionageConnection):
    def __init__(self, cipher: BlockCiphers.BlockCipher, ip: str, port: int, messageHandler):
        self.clients = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not self.sock:
            raise IOError('Could not create the server socket')
        self.nextId = 0
        self.bufferSize = 1024
        self.serverRunning = True
        try:
            self.sock.bind((ip, port))
        except socket.error as err:
            raise IOError(f'Address binding failed. Error:\n{err}')

        super().__init__(cipher, ip, port, messageHandler)

    def listen(self, numClients: int):
        self.sock.listen(numClients)
        while self.serverRunning:
            client, addr = self.sock.accept()
            client.settimeout(120) # 120 second timeout
            
            self.clients[self.nextId] = client

            self.sendMessage('Thanks for connecting, your id is ' + str(self.nextId), client)
            threading.Thread(target=self.listenToClient, 
                args=(client, addr, self.nextId)).start()
            print(addr, 'connected - id:', self.nextId)
            self.nextId += 1
        os._exit(1)

    def listenToClient(self, client: socket.socket, addr: str, id: int):
        while self.serverRunning:
            try:
                if self.clients[id] == None:
                    raise Exception()
                payload = client.recv(self.bufferSize)
                if payload:
                    plaintext = self.decodeReceived(payload)
                    self.messageHandler(f'{str(addr)} [id - {id}]: {plaintext}')
                else:
                    self.messageHandler(f'{addr} disconnected!')
                    raise Exception()
            except:
                client.close()
                print('TCP socket connection to client', id, 'is terminated')
                del self.clients[id]
                return
    
    def send(self, message: str, clientId: int):
        self.sendMessage(message, self.clients[clientId])

    def stop(self):
        self.serverRunning = False
        for clientId in self.clients.keys():
            self.clients[clientId] = None
        return

    def start(self, maxAllowedConnections: int):
        self.listen(maxAllowedConnections)

    def broadcast(self, message: str):
        for client in self.clients.values():
            try:
                self.sendMessage(message, client)
            except:
                continue
    

if __name__ == '__main__':
    # configure cipher and server
    port = 5005
    cipher = BlockCiphers.AES('cbc', 123456789, 987654321)
    server = None
    try:
        server = EspionageServer(cipher, '127.0.0.1', port, print)
    except IOError  as err:
        print('Error during server initialization:')
        print(err)
        sys.exit(1)

    # start listening
    print(f'listening on port {port}')
    threading.Thread(target=server.start, args=((5, )) ).start()
    print(f'You may enter a broadcast message, enter ".exit" to destroy server')
    while True:
        try:
            message = input('>>')
            if message == '.exit':
                print('Terminating server')
                server.stop()
                print('terminated')
                break
            server.broadcast(message)
        except:
            print('terminated with exception')
    print('bye!')