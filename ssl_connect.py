
from time import time
from benchlib import driver

from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import SSL4ServerEndpoint, SSL4ClientEndpoint

from ssl import cert
from accepts import CloseConnection, Client


class WriteOneByte(Protocol):
    def connectionMade(self):
        self.transport.write("x")



class Client(Client):
    protocol = WriteOneByte



def main(reactor, duration):
    concurrency = 50

    interface = '127.0.0.%d' % (int(time()) % 254 + 1,)

    contextFactory = cert.options()
    factory = Factory()
    factory.protocol = CloseConnection
    serverEndpoint = SSL4ServerEndpoint(
        reactor, 0, contextFactory, interface=interface)

    listen = serverEndpoint.listen(factory)
    def cbListening(port):
        client = Client(
            reactor, SSL4ClientEndpoint(
                reactor, interface, port.getHost().port,
                contextFactory, bindAddress=(interface, 0)))
        return client.run(concurrency, duration)
    listen.addCallback(cbListening)
    return listen


if __name__ == '__main__':
    import sys
    import ssl_connect
    driver(ssl_connect.main, sys.argv)