
from __future__ import division

from twisted.python.log import err
from twisted.internet.defer import Deferred
from twisted.names.dns import DNSDatagramProtocol
from twisted.names.server import DNSServerFactory
from twisted.names import hosts, client

from benchlib import Client, driver


class Client(Client):
    def __init__(self, reactor, portNumber):
        self._resolver = client.Resolver(servers=[('127.0.0.1', portNumber)])
        super(Client, self).__init__(reactor)


    def _request(self):
        d = self._resolver.lookupAddress('localhost')
        d.addCallback(self._continue)
        d.addErrback(self._stop)



def report(requestCount, duration):
    print '%s req/sec (%s requests in %s seconds)' % (
        requestCount / duration, requestCount, duration)



def main(reactor, iterations=1):
    duration = 5 * iterations
    concurrency = 10

    controller = DNSServerFactory([hosts.Resolver()])
    port = reactor.listenUDP(0, DNSDatagramProtocol(controller))
    client = Client(reactor, port.getHost().port)
    d = client.run(concurrency, duration)
    d.addCallbacks(report, err, callbackArgs=(duration,))
    return d


if __name__ == '__main__':
    import sys
    driver(main, sys.argv)
