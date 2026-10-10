export const LAB = `import socket,threading
def serve(port,reply):
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind(('0.0.0.0',port))
    listener.listen(16)
    while True:
        conn,_=listener.accept()
        threading.Thread(target=answer,args=(conn,reply),daemon=True).start()
def answer(conn,reply):
    with conn:
        try: conn.recv(4096)
        except OSError: return
        conn.sendall(reply)
redis_body=b'# Server\\r\\nredis_version:7.2.4\\r\\n'
redis=b'$%d\\r\\n' % len(redis_body) + redis_body + b'\\r\\n'
elastic_body=b'{"name":"lab","cluster_name":"lab","version":{"number":"8.15.2"},"tagline":"You Know, for Search"}'
elastic=b'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n' % len(elastic_body) + elastic_body
threading.Thread(target=serve,args=(6379,redis),daemon=True).start()
threading.Thread(target=serve,args=(6381,b'-NOAUTH Authentication required.\\r\\n'),daemon=True).start()
serve(9200,elastic)
`
