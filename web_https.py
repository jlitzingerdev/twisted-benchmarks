import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, asymmetric
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          PrivateFormat,
                                                          NoEncryption)
from cryptography import x509
from twisted.web import client
from twisted.web.server import Site
from twisted.web.static import Data
from twisted.web.resource import Resource
from twisted.internet.ssl import (Certificate, KeyPair, PrivateCertificate,
                                  trustRootFromCertificates)

from benchlib import Client, driver

"""
This benchmark starts a Twisted Web server secured with TLS and makes
as many requests as possible in a fixed period of time.  A certificate
chain is generated as part of the test and consists of:
    Server -> Intermediate -> Root

To simulate actual validation overhead.

The following borrowed heavily from test_authentication in the txkube
project.

https://github.com/LeastAuthority/txkube

"""

rootKey, intermediateKey, serverKey = tuple(
    asymmetric.rsa.generate_private_key(public_exponent=65537,
                                        key_size=2048,
                                        backend=default_backend())
    for i in range(3)
)

def createCert(issuer, subject, privateKey, canSign, signingKey):
    issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer)])

    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)])

    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        privateKey.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False
    )

    if canSign:
        builder = builder.add_extension(
            x509.BasicConstraints(True, None),
            critical=True
        )

    return builder.sign(signingKey, hashes.SHA256(), default_backend())

rootCert = createCert(u"root", u"root", rootKey, True, rootKey)
intermediateCert = createCert(
    u"root",
    u"intermediate",
    intermediateKey,
    True,
    rootKey
)

serverCert = createCert(
    u"intermediate",
    u"server",
    serverKey,
    False,
    intermediateKey
)

serverPrivate = serverKey.private_bytes(
    Encoding.DER,
    PrivateFormat.TraditionalOpenSSL,
    NoEncryption()
)

trustRoot = trustRootFromCertificates(
    [Certificate.loadPEM(rootCert.public_bytes(Encoding.PEM)),
     Certificate.loadPEM(intermediateCert.public_bytes(Encoding.PEM))]
)

privCert = PrivateCertificate.fromCertificateAndKeyPair(
    Certificate.loadPEM(serverCert.public_bytes(Encoding.PEM)),
    KeyPair.load(serverPrivate)
)

root = Resource()
root.putChild(b'', Data(b"Hello, world", "text/plain"))

class TLSClient(Client):

    def __init__(self, reactor, port):
        self._host = b'https://localhost:%d/' % port.getHost().port
        cf = client.BrowserLikePolicyForHTTPS(trustRoot=trustRoot)
        self._agent = client.Agent(reactor, contextFactory=cf)
        super(TLSClient, self).__init__(reactor)

    def _request(self):
        d = self._agent.request(b'GET', self._host)
        d.addCallbacks(self._read, self._stop)

    def _read(self, response):
        d = client.readBody(response)
        d.addCallback(self._continue)
        d.addErrback(self._stop)


def main(reactor, duration):
    concurrency = 10
    port = reactor.listenSSL(
        0,
        Site(root),
        privCert.options(),
        backlog=128,
        interface='127.0.0.1'
    )

    client = TLSClient(reactor, port)
    d = client.run(concurrency, duration)

    def cleanup(passthrough):
        d = port.stopListening()
        d.addCallback(lambda ignored: passthrough)
        return d
    d.addBoth(cleanup)
    return d


if __name__ == '__main__':
    import sys
    import web_https
    driver(web_https.main, sys.argv)
