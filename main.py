import sipproxy
import logging
import socketserver


logging.basicConfig(
    filename='call.log',
    level=logging.INFO,
    format='%(asctime)s %(message)s',
    datefmt='[%d.%m.%Y %H:%M:%S]'
)

proxy = socketserver.UDPServer(('0.0.0.0', 5060), sipproxy.SIPProxy)
proxy.serve_forever() 
