from cryptoran import blockcipher, keyexchange
from PigeonConnection import PigeonConnection
import socket, select, sys, threading

class PigeonServer(PigeonConnection):
    '''
    Multithreaded TCP socket server. Provides encrypted communication
    '''

    def __init__(self, ip: str, port: int, messageHandler: callable, 
            connectionHandler: callable, maxConnections: int, cipherIV = None, cipher = None):
        # Network
        self.bufferSize = 1024
        self.clients = {}
        self.nextId = 0
        self.serverRunning = True
        self.maxConnections = maxConnections
        self.connectionHandler = connectionHandler
        self.printLock = threading.Lock()

        # Encryption
        self.cipher = None
        if cipher:
            self.dh = keyexchange.DiffieHellman(primeLength=256)
            self.dhParams = self.dh.generateSecret()
            self.BlockCipher = cipher
            self.iv = cipherIV
            self.cipher = cipher

        # Configuration
        self.serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not self.serverSock:
            raise IOError('Could not create the server socket')
        try:
            self.serverSock.bind((ip, port))
        except socket.error as err:
            raise IOError(f'Address binding failed. Error:\n{err}')

        super().__init__(ip, port, messageHandler)

    def listen(self):
        # start listening for max <self.maxConnections> connections to the server socket
        self.serverSock.listen(self.maxConnections)

        while self.serverRunning:
            # check if there is an incoming connection to the server
            readable, _, _ = select.select([self.serverSock], [], [], 0.1)
            for incoming in readable:
                if incoming == self.serverSock:
                    # accept the connection
                    client, addr = self.serverSock.accept()
                    client.settimeout(120)

                    cipher = None
                    if self.cipher:
                        # negotiate on key using Diffie Hellman protocol
                        # 1 - send dh params to client
                        self.sendUnencrypted(self.dhParams, client)

                        # 2 - listen for Diffie-Hellman input
                        dhRaw = client.recv(512)
                        dhInput = self.decodeUnencrypted(dhRaw)
                        sharedKey = self.dh.generateSharedKey(dhInput)
                        cipher = self.BlockCipher('cbc', sharedKey, self.iv)

                    clientPair = (client, cipher)
                    self.clients[self.nextId] = clientPair
                    
                    # start a new thread listening for incoming messages from the new client
                    threading.Thread(target=self.listenToClient, args=(addr, self.nextId, clientPair)).start()
                    
                    # expose the new connection to class user
                    self.connectionHandler(addr, self.nextId)
                    self.nextId += 1
        print('stopped listening for incoming TCP connections') # debug

    def listenToClient(self, addr: str, id: int, clientPair):
        self.sendMessage('Thanks for connecting, your id is ' + str(self.nextId), clientPair)

        while self.serverRunning:
            try:
                if self.clients[id] == None: # another method has requested disconnection of client
                    raise Exception()
                readable, _, _ = select.select([clientPair[0]], [], [], 0.1)

                for _ in readable:
                    payload = clientPair[0].recv(self.bufferSize)
                    if not payload:
                        raise Exception()
                    else:
                        plaintext = self.decodeReceived(payload, clientPair[1])
                        with self.printLock:
                            self.messageHandler(id, addr, plaintext)
            except:
                clientPair[0].close()
                print('TCP socket connection to client', id, 'is terminated')
                del self.clients[id]
                return
        print(f'stopped listening client {id}')
    
    def send(self, message: str, clientId: int):
        self.sendMessage(message, self.clients[clientId])

    def stop(self):
        self.serverRunning = False
        for clientId in self.clients.keys():
            self.clients[clientId] = None

    def start(self):
        self.listen()

    def broadcast(self, message: str):
        for clientPair in self.clients.values():
            try:
                self.sendMessage(message, clientPair)
            except:
                continue
    

if __name__ == '__main__':
    aesiv = 0xed7ef412977a7df3af9e67307bd2214b
    ip, port = None, None
    unsafe = False

    try:
        ip = sys.argv[1]
        port = int(sys.argv[2])
        if len(sys.argv) > 3 and sys.argv[3] == '--unsafe':
            unsafe = True
    except:
        print('usage: python server.py ip port [--unsafe]')
        print(sys.argv)
        sys.exit()

    server = None

    def messageHandler(id, address, message):
        print(f'{str(address)} [id - {id}]: {message}')
    
    def connectionHandler(address, id):
        print(f'{address} connected - id: {id}')

    # configure cipher and server
    try:
        if unsafe:
            server = PigeonServer(ip, port, messageHandler, connectionHandler, 5)
        else:
            server = PigeonServer(ip, port, messageHandler, connectionHandler, 5, aesiv, blockcipher.AES)
    except IOError  as err:
        print('Error during server initialization:')
        print(err)
        sys.exit(1)

    # start listening
    print(f'listening on port {port}')
    threading.Thread(target=server.start).start()
    print(f'You may enter a broadcast message.\nEnter ".exit" or KeyboardInterrupt to destroy server')
    while True:
        try:
            message = input()
            if message == '.exit':
                raise KeyboardInterrupt
            server.broadcast(message)
        except KeyboardInterrupt:
            print('\nTerminating server')
            server.stop()
            break
    print('main thread dying')
