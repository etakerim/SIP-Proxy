import re
import socketserver
from time import time
import logging
import settings


registry = {}
calling = set()


class SIPProxy(socketserver.BaseRequestHandler):

    FROM = re.compile(r'^From\s*:', re.I)
    TO = re.compile(r'^To\s*:', re.I)

    NOTIFICATION = re.compile(r'(SUBSCRIBE|PUBLISH|NOTIFY)')
    CONTENT_LENGTH = re.compile(r'^Content-Length:\s*:', re.I)
    VIA = re.compile(r'^(Via|v)\s*:', re.I)
    CALL_ID = re.compile(r'^Call-ID\s*:\s*(.*)$', re.I)
    ROUTE = re.compile(r'^Route\s*:', re.I)
    CONTACT = re.compile(r'^Contact\s*:', re.I)
    EXPIRES = re.compile(r'^Expires\s*:\s*(.*)$', re.I)
    STATUS_CODE = re.compile(r'^SIP/2.0 ([^ ]*)')
    SIP_CODE = re.compile(r'^SIP/2.0\s+(\d+)')

    SIP_URI = re.compile(r'sip:([^@]*)@([^;>$]*)')
    EXPIRES_OPT = re.compile(r'expires=([^;$]*)')
    BRANCH_OPT = re.compile(r';branch=([^;]*)')
    RPORT_OPT = re.compile(r';rport$|;rport;')

    VIA_HEADER = f'Via: SIP/2.0/UDP {settings.SIP_IP}:{settings.SIP_PORT}'
    RECORD_ROUTE = f'Record-Route: <sip:{settings.SIP_IP}:{settings.SIP_PORT};lr>'

    def expired(self, target):
        gone = registry[target]['validity'] <= int(time())
        if gone:
            registry.pop(target, None)
        return gone

    def participants(self):
        return (
            self.find_client(self.FROM),
            self.find_client(self.TO)
        )

    def find_client(self, direction):
        for header in self.headers:
            if direction.match(header):
                if (m := re.search(self.SIP_URI, header)) is not None:
                    return f'{m.group(1)}@{m.group(2)}'

    def call_id(self):
        for header in self.headers:
            if (m := re.search(self.CALL_ID, header)) is not None:
                return f'{m.group(1)}'

    def response(self, code):
        self.headers[0] = f'SIP/2.0 {code}'

        for i, header in enumerate(self.headers):
            if self.TO.match(header) is not None and ';tag' not in header:
                self.headers[i] = f'{header};tag=123456'

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
            change = source not in registry

            registry[source] = {
                'socket': self.socket,
                'contact': contact,
                'client': self.client_address,
                'validity': validity
            }
            print(registry)
            if change:
                logging.info(f'{source} sa registroval na ústredni: {list(registry.keys())}')

    def sip_invite(self):
        source = self.find_client(self.FROM)
        if not source or source not in registry:
            return self.response('400 Volajuci nie je registrovany')

        destination = self.find_client(self.TO)
        if not destination:
            return self.response('500 Interná chyba servera')

        if destination not in registry or self.expired(destination):
            return self.response('480 Volany je docasne nedostupny')

        self.resend(destination)

    def sip_other(self):
        source = self.find_client(self.FROM)
        if not source or source not in registry:
            return self.response('400 Volajuci nie je registrovany')

        destination = self.find_client(self.TO)
        if not destination:
            return self.response('500 Interna chyba servera')

        if destination not in registry or self.expired(destination):
            return self.response('406 Neprijatelne')

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
                response.append(self.RECORD_ROUTE)

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
        try:
            self.headers = message.decode('utf8').split('\r\n')
        except Exception:
            return
        request = self.headers[0]

        if request and 'SIP/2.0' in request:
            if request.startswith('REGISTER'):
                self.sip_register()
                self.response('200 0K')

            elif request.startswith('INVITE'):
                self.sip_invite()

                a, b = self.participants()
                call = self.call_id()
                if call not in calling:
                    logging.info(f'Hovor: {call} , <{a}> volá účastníka <{b}>')
                    calling.add(call)

            elif request.startswith('ACK'):
                self.resend_to_destination()

                a, b = self.participants()
                call = self.call_id()
                if call in calling:
                    logging.info(f'Hovor: {call}, <{b}> prijal hovor od <{a}>')

            elif self.STATUS_CODE.match(request):
                if (m := self.SIP_CODE.match(request)) is not None:
                    code = m.group(1)
                    if code == '486':
                        self.headers[0] = f'SIP/2.0 {code} Obsadene'
                    if code == '100':
                        self.headers[0] = f'SIP/2.0 {code} Volame'
                    if code == '603' or code == '486':
                        a, b = self.participants()
                        call = self.call_id()
                        if call in calling:
                            logging.info(f'Hovor: {call}, <{b}> odmietol hovor od <{a}>')
                            calling.remove(call)

                self.resend_to_source()

            elif self.NOTIFICATION.match(request):
                self.response('200 0K')

            else:
                self.sip_other()

                if request.startswith('BYE'):
                    a, b = self.participants()
                    call = self.call_id()
                    if call in calling:
                        logging.info(f'Hovor: {call}, <{a}> ukončil hovor od <{b}>')
                        calling.remove(call)

                elif request.startswith('CANCEL'):
                    a, b = self.participants()
                    call = self.call_id()
                    if call in calling:
                        logging.info(f'Hovor: {call}, <{a}> zrušil hovor ku <{b}>')
                        calling.remove(call)
