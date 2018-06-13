from cryptoran import BlockCiphers
from EspionageConnection import EspionageConnection
import socket, select, sys, threading

class EspionageServer(EspionageConnection):
    '''
    Multithreaded TCP socket server. All comms are encrypted.
    '''

    def __init__(self, cipher: BlockCiphers.BlockCipher, ip: str, 
            port: int, messageHandler, maxConnections: int):
        self.bufferSize = 1024
        self.clients = {}
        self.nextId = 0
        self.serverRunning = True
        self.maxConnections = maxConnections

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
        self.serverSock.listen(self.maxConnections)
        inputs = [self.serverSock]
        while self.serverRunning:
            inready, outready, excready = select.select(inputs, [], [], 0.1)
            for incoming in inready:
                if incoming == self.serverSock:
                    client, addr = self.serverSock.accept()
                    client.settimeout(120)
                    if not incoming:
                        raise Exception('Client Disconnected in listen()')
            
                self.clients[self.nextId] = client

                self.sendMessage('Thanks for connecting, your id is ' + str(self.nextId), client)
                threading.Thread(target=self.listenToClient, 
                    args=(client, addr, self.nextId)).start()
                print(addr, 'connected - id:', self.nextId)
                self.nextId += 1
        print('stopped listening for incoming TCP connections')

    def listenToClient(self, client: socket.socket, addr: str, id: int):
        inputs = [self.serverSock]
        while self.serverRunning:
            try:
                if self.clients[id] == None: # another method has requested disconnection of client
                    raise Exception()
                inready, outready, excready = select.select(inputs, [], [], 0.1)
                for incoming in inready:
                    payload = client.recv(self.bufferSize)
                    if not payload:
                        raise Exception()
                    else:
                        plaintext = self.decodeReceived(payload)
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
    # configure cipher and server
    def messageHandler(id, address, message):
        print(f'{str(address)} [id - {id}]: {message}')

    port = 5005
    cipher = BlockCiphers.AES('cbc', 123456789, 987654321)
    server = None
    try:
        server = EspionageServer(cipher, '127.0.0.1', port, messageHandler, 5)
    except IOError  as err:
        print('Error during server initialization:')
        print(err)
        sys.exit(1)

    # start listening
    print(f'listening on port {port}')
    threading.Thread(target=server.start).start()
    print(f'You may enter a broadcast message, CTRL + C to destroy server')
    while True:
        try:
            message = input('>>')
            server.broadcast(message)
        except KeyboardInterrupt:
            print('\nTerminating server')
            server.stop()
            break
    print('main thread finishing')