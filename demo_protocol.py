import socket, struct, sys, time
HEADER=struct.Struct('!2sBBI')
def frame(text):
    b=text.encode('utf-8'); return HEADER.pack(b'NS',1,1,len(b))+b
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='server':
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',19090)); s.listen(); print('测试服务监听 127.0.0.1:19090',flush=True)
            while True:
                c,addr=s.accept()
                with c:
                    print('连接:',addr,flush=True)
                    while True:
                        data=c.recv(4096)
                        if not data: break
                        print('收到:',data,flush=True); c.sendall(frame('服务端已收到'))
    else:
        with socket.create_connection(('127.0.0.1',19090)) as s:
            print('客户端已连接；输入文字发送，输入 quit 退出。',flush=True)
            while True:
                msg=input('> ')
                if msg=='quit': break
                s.sendall(frame(msg)); print('收到:',s.recv(4096))
