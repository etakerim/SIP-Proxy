import re
from socketserver import UDPServer, BaseRequestHandler

registry = {}
SIP_URI = 'sip:([^@]*)@([^;>$]*)'


class SIPProxy(BaseRequestHandler):

    def forward_response(self, code):
        self.headers[0] = f'SIP/2.0 {code}'

        for i, header in enumerate(self.headers):
            if header.startswith('To:') and ';tag' not in header:
                self.headers[i] = f'{self.headers[i]};tag=123456'

            elif header.startswith('Content-Length:'):
                self.headers[i] = 'Content-Length: 0'

        message = '\r\n'.join(self.headers).encode('utf8')
        self.socket.sendto(message, self.client_address)

    def sip_register(self):
        for header in self.headers:
            if header.startswith('To:'):
                m = re.search(SIP_URI, header)
                if m is not None:
                    source = f'{m.group(1)}@{m.group(2)}'
            elif header.startswith('Contact:'):
                m = re.search(SIP_URI, header)
                if m is not None:
                    contact = m.group(2)

        registry[source] = [
            contact,
            self.socket,
            self.client_address
        ]
        self.forward_response('200 0K')

    def handle(self):
        message, self.socket = self.request
        self.headers = message.decode('utf8').split('\r\n')
        request = self.headers[0]

        if len(request) > 0 and 'SIP/2.0' in request:
            if request.startswith('REGISTER'):
                self.sip_register()
                print(registry)


if __name__ == '__main__':
    proxy = UDPServer(('0.0.0.0', 5060), SIPProxy)
    proxy.serve_forever()