# pigeon
Encrypted server-client communication using cryptoran.

## So what is pigeon?

Pigeon provides an interface for encrypted server-client communication. It is being built with the purpose of simplifying such interactions. It is a multi-threaded server, not an async one thus Espionage is not intended for scalable large networks.

### Current implementation features

* Hosts negotiate on a shared key using Diffie-Hellman protocol
* Further communication is encrypted by AES-128 in CBC mode with the key supplied from DH
* Communication runs over TCP

## Usage

__Server__  
To start a server instance, simply launch the server.py file with ip and port arguments.
```bash
$ python server.py 0.0.0.0 5050
```

__Client__  
Starting a client instance is as easy. Launch client.py specifying ip and port.
```bash
$ python client.py 192.168.1.105 5050
```

To integrate into your own Python 3 module, you may import server and client classes; however, such functionality is narrowly tested. Future versions will be working primarily towards this usage.

```python
from server import PigeonServer
from cryptoran import blockcipher # pip install cryptoran

cipher = blockcipher.AES('cbc', 1234567891011, 546372828374)
server = PigeonServer(cipher, '192.168.1.5', 5000, print,
    lambda addr, id: print(f'{address} connected - id: {id}'))
server.start() # Server listening on port 5000
```

## Important

Pigeon relies on cryptoran, which I am building for educational purposes only. You should __not__ rely neither on Pigeon nor cryptoran for ensuring security in your system.
