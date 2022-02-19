import re
import socketserver
import secrets
from time import time


registry = {}


class SIPProxy(socketserver.BaseRequestHandler):

    FROM = re.compile(r'^From\s*:', re.I)
    TO = re.compile(r'^To\s*:', re.I)

    CONTENT_LENGTH = re.compile(r'^Content-Length:\s*:', re.I)
    VIA = re.compile(r'^(Via|v)\s*:', re.I)
    ROUTE = re.compile(r'^Route\s*:', re.I)
    CONTACT = re.compile(r'^Contact\s*:', re.I)
    EXPIRES = re.compile(r'^Expires\s*:\s*(.*)$', re.I)

    SIP_URI = re.compile(r'sip:([^@]*)@([^;>$]*)')
    EXPIRES_OPT = re.compile(r'expires=([^;$]*)')
    BRANCH_OPT = re.compile(r';branch=([^;]*)')
    RPORT_OPT = re.compile(r';rport$|;rport;')
    VIA_HEADER = 'Via: SIP/2.0/UDP 192.168.1.103:5060'

    def expired(target):
        available = registry[target]['validity'] > int(time())
        if not available:
            registry.pop(target, None)
        return available

    def response(self, code):
        self.headers[0] = f'SIP/2.0 {code}'

        for i, header in enumerate(self.headers):
            if self.TO.match(header) is not None and ';tag' not in header:
                tag = secrets.token_urlsafe(4)
                self.headers[i] = f'{header};tag={tag}'

            elif self.VIA.match(header):
                if ';rport' in header:
                    self.headers[i] = header.replace(
                        'rport', 'received=%s;rport=%d' % self.client_address
                    )
                else:
                    self.headers[i] = (
                        f'{header};received={self.client_address[0]}'
                    )

            elif self.CONTENT_LENGTH.match(header):
                self.headers[i] = 'Content-Length: 0'

        message = '\r\n'.join(self.headers).encode('utf8')
        self.socket.sendto(message, self.client_address)

    def find_client(self, direction):
        for header in self.headers:
            if direction.match(header):
                if (m := re.search(self.SIP_URI, header)) is not None:
                    return f'{m.group(1)}@{m.group(2)}'

    def sip_register(self):
        for header in self.headers:
            if self.TO.match(header):
                if (m := self.SIP_URI.search(header)) is not None:
                    source = f'{m.group(1)}@{m.group(2)}'

            elif self.CONTACT.match(header):
                if (m := self.SIP_URI.search(header)) is not None:
                    contact = m.group(2)
                if (m := self.EXPIRES_OPT.search(header)) is not None:
                    expires = int(m.group(1))

            elif (m := self.EXPIRES.match(header)) is not None:
                expires = int(m.group(1))

        if expires == 0:
            registry.pop(source, None)
        else:
            validity = int(time()) + expires
            registry[source] = {
                'socket': self.socket,
                'contact': contact,
                'client': self.client_address,
                'validity': validity
            }

        self.response('200 0K')

    def sip_invite(self):
        source = self.find_client(self.FROM)
        if not source or source not in registry:
            return self.response('400 Bad Request')

        destination = self.find_client(self.TO)
        if not destination:
            return self.response('500 Server Internal Error')

        if destination not in registry and self.expired(destination):
            return self.response('480 Temporarily Unavailable')

        self.resend(destination)

    def sip_other(self):
        source = self.find_client(self.FROM)
        if not source or source not in registry:
            return self.response('400 Bad Request')

        destination = self.find_client(self.TO)
        if not destination:
            return self.response('500 Server Internal Error')

        if destination not in registry and self.expired(destination):
            return self.response('406 Not Acceptable')

        self.resend(destination)

    def resend_to_source(self):
        self.resend(self.find_client(self.FROM))

    def resend_to_destination(self):
        self.resend(self.find_client(self.TO))

    def resend(self, target):
        if not target or target not in registry:
            return

        response = []
        for header in self.headers:
            if len(response) == 1:
                response.append('Record-Route: <sip:192.168.1.103:5060;lr>')

            if self.VIA.match(header):
                if (m := self.BRANCH_OPT.search(header)) is not None:
                    response.append(f'{self.VIA_HEADER};branch={m.group(1)}')

                if (m := self.RPORT_OPT.search(header)) is not None:
                    via = header.replace(
                        'rport', "received=%s;rport=%d" % self.client_address
                    )
                else:
                    via = f'{header};received={self.client_address[0]}'
                response.append(via)
            elif not self.ROUTE.match(header):
                response.append(header)

        message = '\r\n'.join(response).encode('utf8')
        entity = registry[target]
        entity['socket'].sendto(message, entity['client'])

    def handle(self):
        message, self.socket = self.request
        self.headers = message.decode('utf8').split('\r\n')
        request = self.headers[0]

        if request and 'SIP/2.0' in request:
            if request.startswith('REGISTER'):
                self.sip_register()
                print(registry)
            elif request.startswith('INVITE'):
                self.sip_invite()
            elif request.startswith('ACK'):
                self.resend_to_destination()
            elif re.search('^SIP/2.0 ([^ ]*)', request):  # Code
                self.resend_to_source()
            else:
                self.sip_other()


if __name__ == '__main__':
    proxy = socketserver.UDPServer(('0.0.0.0', 5060), SIPProxy)
    proxy.serve_forever()
