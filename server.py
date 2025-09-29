#!/usr/bin/env python3
# server.py
import socket
import threading
import os

HOST = "0.0.0.0"
PORT = 5000
STORAGE_DIR = "storage"

os.makedirs(STORAGE_DIR, exist_ok=True)

def recvline(conn):
    """Recebe até newline ou fim (utilitário simples)."""
    data = b""
    while True:
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
        if chunk == b"\n":
            break
    return data.decode('utf-8', errors='ignore').strip()

def handle_client(conn, addr):
    print(f"[+] Conexão de {addr}")
    try:
        while True:
            header = recvline(conn)
            if not header:
                break

            parts = header.split(" ", 1)
            cmd = parts[0].upper()

            if cmd == "LIST":
                files = os.listdir(STORAGE_DIR)
                response = "\n".join(files) if files else "(vazio)"
                conn.sendall((response + "\n").encode("utf-8"))

            elif cmd == "PUT":
                if len(parts) < 2:
                    conn.sendall(b"ERRO: nome do arquivo ausente\n")
                    continue
                filename = os.path.basename(parts[1])
                filepath = os.path.join(STORAGE_DIR, filename)

                if os.path.exists(filepath):
                    conn.sendall(b"ERRO: arquivo ja existe\n")
                    continue

                # sinaliza prontidão para receber o tamanho
                conn.sendall(b"READY\n")
                size_line = recvline(conn)
                try:
                    filesize = int(size_line.strip())
                except:
                    conn.sendall(b"ERRO: tamanho invalido\n")
                    continue
                conn.sendall(b"OK\n")

                received = 0
                with open(filepath, "wb") as f:
                    while received < filesize:
                        chunk = conn.recv(min(4096, filesize - received))
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)

                print(f"[+] Arquivo {filename} recebido ({received} bytes)")
                conn.sendall(f"RECEIVED {received}\n".encode())

            elif cmd == "QUIT":
                print(f"[-] Cliente {addr} desconectou")
                conn.sendall(b"BYE\n")
                break

            else:
                conn.sendall(b"ERRO: comando invalido\n")

    except Exception as e:
        print(f"[!] Erro com cliente {addr}: {e}")
    finally:
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"Servidor escutando em {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    main()
