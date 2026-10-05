"""Ephemeral authenticated workbench for browser acceptance; no provider calls."""
import signal
import sys
from http.server import ThreadingHTTPServer
from eval.vnext_arbitration import Arbitration
from agent.review_service import Handler

fixture=Arbitration();fixture.setUp()
signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
try:
    fixture.submit('r1','confirmed_risk')
    fixture.submit('r2','benign')
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    print('http://127.0.0.1:'+str(server.server_port),flush=True)
    server.serve_forever()
finally:
    fixture.tearDown()
