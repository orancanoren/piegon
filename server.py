from cryptoran import BlockCiphers
from EspionageConnection import EspionageConnection
import socket, select, sys, threading

class EspionageServer(EspionageConnection):
    '''
    Multithreaded TCP socket server. All comms are encrypted.
    '''

    def __init__(self, cipher: BlockCiphers.BlockCipher, ip: str, 
            port: int, messageHandler: callable, connectionHandler: callable, maxConnections: int):
        self.bufferSize = 1024
        self.clients = {}
        self.nextId = 0
        self.serverRunning = True
        self.maxConnections = maxConnections
        self.connectionHandler = connectionHandler
        self.printLock = threading.Lock()

        # set up the server socket
        self.serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not self.serverSock:
            raise IOError('Could not create the server socket')
        try:
            self.serverSock.bind((ip, port))
        except socket.error as err:
            raise IOError(f'Address binding failed. Error:\n{err}')

        super().__init__(cipher, ip, port, messageHandler)

    def listen(self):
        # start listening for max <self.maxConnections> connections to the server socket
        self.serverSock.listen(self.maxConnections)

        while self.serverRunning:
            # check if there is an incoming connection to the server
            readable, _, _ = select.select([self.serverSock], [], [], 0.1)
            for incoming in readable:
                if incoming == self.serverSock:
                    # accept the connection and add the client socket to the list of client sockets
                    client, addr = self.serverSock.accept()
                    client.settimeout(120)
                    self.clients[self.nextId] = client

                    # send greeting message to the new client
                    self.sendMessage('Thanks for connecting, your id is ' + str(self.nextId), client)
                    # start a new thread listening for incoming messages from the new client
                    threading.Thread(target=self.listenToClient, args=(client, addr, self.nextId)).start()
                    # expose the new connection to class user
                    self.connectionHandler(addr, self.nextId)
                    self.nextId += 1
        print('stopped listening for incoming TCP connections') # debug

    def listenToClient(self, client: socket.socket, addr: str, id: int):
        while self.serverRunning:
            try:
                if self.clients[id] == None: # another method has requested disconnection of client
                    raise Exception()
                readable, _, _ = select.select([client], [], [], 0.1)

                for _ in readable:
                    payload = client.recv(self.bufferSize)
                    if not payload:
                        raise Exception()
                    else:
                        plaintext = self.decodeReceived(payload)
                        with self.printLock:
                            self.messageHandler(id, addr, plaintext)
            except:
                client.close()
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
            print('set to none:', self.clients[clientId])

    def start(self):
        self.listen()

    def broadcast(self, message: str):
        for client in self.clients.values():
            try:
                self.sendMessage(message, client)
            except:
                continue
    

if __name__ == '__main__':
    aeskey = 0xa359d14d4ba52b820daf40c5c4fa5568
    aesiv = 0xed7ef412977a7df3af9e67307bd2214b
    ip, port = None, None

    try:
        ip = sys.argv[1]
        port = int(sys.argv[2])
    except:
        print('usage: python server.py ip port')

    cipher = BlockCiphers.AES('cbc', aeskey, aesiv)
    server = None

    def messageHandler(id, address, message):
        print(f'{str(address)} [id - {id}]: {message}')
    
    def connectionHandler(address, id):
        print(f'{address} connected - id: {id}')

    # configure cipher and server
    try:
        server = EspionageServer(cipher, ip, port, messageHandler, connectionHandler, 5)
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