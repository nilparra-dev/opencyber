// Redis 7.2 pinned by digest. The same digest is used by fork-cyber-database-auth.test.ts.
export const REDIS = "redis@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0"

// Each request the lab receives is printed before it is answered, so a test can prove exactly what was sent.
// Ports: 6379 answers INFO, 6380 requires a password, 9200 answers GET / unauthenticated, 9201 requires one.
export const RECORDING_LAB = `import socket,threading
def serve(port,reply,name):
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind(('0.0.0.0',port))
    listener.listen(16)
    while True:
        conn,_=listener.accept()
        threading.Thread(target=answer,args=(conn,reply,name),daemon=True).start()
def answer(conn,reply,name):
    with conn:
        try: data=conn.recv(4096)
        except OSError: return
        print(name,repr(data),flush=True)
        conn.sendall(reply)
info=b'# Server\\r\\nredis_version:7.2.4\\r\\n'
redis_info=b'$%d\\r\\n' % len(info) + info + b'\\r\\n'
body=b'{"name":"lab","cluster_name":"lab","version":{"number":"8.15.2"}}'
es_ok=b'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n' % len(body) + body
denied=b'{"error":"unauthenticated"}'
es_401=b'HTTP/1.1 401 Unauthorized\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n' % len(denied) + denied
threading.Thread(target=serve,args=(6379,redis_info,'redis-info'),daemon=True).start()
threading.Thread(target=serve,args=(6380,b'-NOAUTH Authentication required.\\r\\n','redis-noauth'),daemon=True).start()
threading.Thread(target=serve,args=(9201,es_401,'es-401'),daemon=True).start()
serve(9200,es_ok,'es-200')
`

// Elasticsearch stand-in for the authentication classification: GET / answers 200 only with the Basic credential in
// ES_SECRET (user:password), and 401 otherwise. No Elasticsearch image is pinned, so this is a protocol stand-in.
export const STAND_IN_ES = `import base64,os
from http.server import BaseHTTPRequestHandler,HTTPServer
valid='Basic '+base64.b64encode(os.environ['ES_SECRET'].encode()).decode()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        ok=self.headers.get('Authorization')==valid
        body=b'{"name":"lab","cluster_name":"lab","version":{"number":"8.15.2"}}' if ok else b'{"error":"unauthenticated"}'
        self.send_response(200 if ok else 401)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*args): pass
HTTPServer(('0.0.0.0',9200),Handler).serve_forever()
`
