
from __future__ import division

from twisted.python.log import err
from twisted.internet.defer import Deferred

from benchlib import Client, driver


class Client(Client):
    def _request(self):
        self._reactor.callLater(0.0, self._continue, None)



def report(requestCount, duration):
    print '%s iter/sec (%s iterations in %s seconds)' % (
        requestCount / duration, requestCount, duration)



def main(reactor, iterations=1):
    duration = 5 * iterations
    concurrency = 10

    client = Client(reactor)
    d = client.run(concurrency, duration)
    d.addCallbacks(report, err, callbackArgs=(duration,))
    return d



if __name__ == '__main__':
    import sys
    driver(main, sys.argv)
