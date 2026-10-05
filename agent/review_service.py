"""Isolated review workbench. No signing key, release role or production writes."""
import argparse
import json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse,parse_qs
from .tenancy import authenticate
from .case_review import detail,review,arbitrate,export_labels
from .investigations import list_cases

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def send(self,status,value,content_type='application/json; charset=utf-8'):
        body=json.dumps(value,ensure_ascii=False).encode() if isinstance(value,(dict,list)) else value
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'")
        self.end_headers();self.wfile.write(body)
    def do_GET(self):
        parsed=urlparse(self.path)
        if parsed.path in ('/','/review.js','/review.css'):
            name={'/':'review.html','/review.js':'review.js','/review.css':'review.css'}[parsed.path]
            mime={'/':'text/html; charset=utf-8','/review.js':'text/javascript; charset=utf-8','/review.css':'text/css; charset=utf-8'}[parsed.path]
            return self.send(200,(Path(__file__).parent/'web'/name).read_bytes(),mime)
        try:
            ctx=authenticate(self.headers.get('Authorization'))
            if parsed.path=='/api/cases':return self.send(200,{'cases':list_cases(ctx)})
            if parsed.path=='/api/case':return self.send(200,detail(ctx,parse_qs(parsed.query).get('task_id',[''])[0]))
            self.send(404,{'error':'not_found'})
        except PermissionError:self.send(403,{'error':'forbidden'})
        except (ValueError,OSError):self.send(400,{'error':'invalid_request_or_unavailable_store'})
    def do_POST(self):
        try:
            ctx=authenticate(self.headers.get('Authorization'))
            if self.path not in ('/api/reviews','/api/arbitrations','/api/labels/export'):return self.send(404,{'error':'not_found'})
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=16384:raise ValueError('body limit')
            request=json.loads(self.rfile.read(length))
            if self.path=='/api/labels/export':
                if not isinstance(request,dict) or set(request)!={'as_of'}:raise ValueError('invalid export contract')
                return self.send(200,export_labels(ctx,request['as_of']))
            self.send(200,(arbitrate if self.path=='/api/arbitrations' else review)(ctx,request))
        except PermissionError:self.send(403,{'error':'forbidden'})
        except (ValueError,KeyError,TypeError):self.send(400,{'error':'invalid_or_stale_review'})

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=8090)
    args=parser.parse_args();ThreadingHTTPServer((args.host,args.port),Handler).serve_forever()
if __name__=='__main__':main()
