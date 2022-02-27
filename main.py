import sipproxy
import logging
import socketserver
import settings


logging.basicConfig(
    filename=settings.LOG_FILENAME,
    level=logging.INFO,
    format='%(asctime)s %(message)s',
    datefmt='[%d.%m.%Y %H:%M:%S]'
)

proxy = socketserver.UDPServer(('0.0.0.0', settings.SIP_PORT), sipproxy.SIPProxy)
proxy.serve_forever()
