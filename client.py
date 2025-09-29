#!/usr/bin/env python3
# client.py
import socket
import os
import time
import argparse
import subprocess
import sys
import threading
import struct

def start_packet_capture(iface, host, port, pcapfile):
    """Tenta iniciar tcpdump para gerar um pcap; retorna subprocess ou None."""
    cmd = ["tcpdump", "-i", iface, "tcp and host " + host, "-w", pcapfile]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc
    except FileNotFoundError:
        print("[!] tcpdump não encontrado. Instale tcpdump ou capture com Wireshark/tshark manualmente.")
    except PermissionError:
        print("[!] Permissão negada para executar tcpdump. Execute com privilégios (sudo) ou capture manualmente.")
    except Exception as e:
        print(f"[!] Erro ao iniciar captura: {e}")
    return None

def stop_packet_capture(proc):
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except:
            pass

def log_connection_file(filename, start, end, bytes_sent, bytes_recv, tcp_info_records=None):
    duration = end - start
    taxa = (bytes_sent + bytes_recv) / duration if duration > 0 else 0
    with open(filename, "w") as f:
        f.write(f"Conexão iniciada: {time.ctime(start)}\n")
        f.write(f"Conexão encerrada: {time.ctime(end)}\n")
        f.write(f"Bytes enviados: {bytes_sent}\n")
        f.write(f"Bytes recebidos: {bytes_recv}\n")
        f.write(f"Duração (s): {duration:.6f}\n")
        f.write(f"Taxa aproximada (bytes/s): {taxa:.2f}\n")
        f.write("\n")
        if tcp_info_records:
            f.write("Registro TCP_INFO (samples durante a conexão):\n")
            for t, raw in tcp_info_records:
                f.write(f"[{time.ctime(t)}] raw({len(raw)} bytes): {raw.hex()}\n")
        f.write("\n-- fim do log --\n")

def collect_tcp_info_periodically(sock, interval, out_list, stop_event):
    """Tenta coletar getsockopt(TCP_INFO) periodicamente; armazena raw bytes."""
    try:
        TCP_INFO = getattr(socket, "TCP_INFO")
    except AttributeError:
        # em algumas plataformas socket.TCP_INFO pode não existir
        return
    while not stop_event.is_set():
        try:
            raw = sock.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 256)
            out_list.append((time.time(), raw))
        except Exception:
            # ignore erros (não essenciais)
            pass
        stop_event.wait(interval)

def recvline(sock):
    data = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            break
        data += ch
        if ch == b"\n":
            break
    return data.decode('utf-8', errors='ignore').strip()

def main():
    parser = argparse.ArgumentParser(description="Cliente do mini-serviço (com instrumentação).")
    parser.add_argument("host", help="IP/host do servidor")
    parser.add_argument("port", type=int, help="porta do servidor")
    parser.add_argument("--capture", action="store_true", help="gerar pcap via tcpdump durante a conexão")
    parser.add_argument("--iface", default="any", help="interface para tcpdump (padrão: any)")
    parser.add_argument("--tcpinfo", action="store_true", help="tentar coletar TCP_INFO (somente Linux)")
    parser.add_argument("--logdir", default="logs", help="diretório para logs e pcaps")
    args = parser.parse_args()

    os.makedirs(args.logdir, exist_ok=True)
    timestamp = int(time.time())
    pcapfile = os.path.join(args.logdir, f"capture_{timestamp}.pcap")
    logfile = os.path.join(args.logdir, f"client_log_{timestamp}.txt")

    capture_proc = None
    if args.capture:
        print(f"[i] Iniciando captura pcap em {pcapfile} (iface={args.iface}) — requer tcpdump e privilégios.")
        capture_proc = start_packet_capture(args.iface, args.host, args.port, pcapfile)
        if not capture_proc:
            print("[!] Falha ao iniciar captura; continuando sem pcap.")

    tcp_info_records = []
    tcpinfo_stop = threading.Event()
    tcpinfo_thread = None

    bytes_sent = 0
    bytes_recv = 0
    start_time = time.time()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((args.host, args.port))
            print(f"[+] Conectado a {args.host}:{args.port}")

            if args.tcpinfo:
                # inicia thread de coleta periódica do TCP_INFO
                tcpinfo_thread = threading.Thread(target=collect_tcp_info_periodically,
                                                  args=(s, 1.0, tcp_info_records, tcpinfo_stop),
                                                  daemon=True)
                tcpinfo_thread.start()

            while True:
                cmd = input(">> ").strip()
                if not cmd:
                    continue

                # enviar o comando (sempre termina em newline para o servidor ler linha)
                tosend = (cmd + "\n").encode('utf-8')
                s.sendall(tosend)
                bytes_sent += len(tosend)

                if cmd.lower() == "list":
                    data = recvline(s)
                    if data is None:
                        print("[!] conexão encerrada pelo servidor")
                        break
                    bytes_recv += len(data.encode())
                    print("Arquivos no servidor:\n", data)

                elif cmd.lower().startswith("put "):
                    filename = cmd.split(" ", 1)[1]
                    if not os.path.exists(filename):
                        print("Arquivo não encontrado localmente.")
                        continue

                    # aguardar READY
                    ready = recvline(s)
                    if not ready:
                        print("[!] servidor fechou a conexão")
                        break
                    bytes_recv += len(ready.encode())
                    if "READY" not in ready:
                        print("Servidor recusou envio:", ready)
                        continue

                    filesize = os.path.getsize(filename)
                    size_line = (str(filesize) + "\n").encode('utf-8')
                    s.sendall(size_line)
                    bytes_sent += len(size_line)

                    ok = recvline(s)
                    bytes_recv += len(ok.encode())
                    if "OK" not in ok:
                        print("Erro na negociação de tamanho:", ok)
                        continue

                    # enviar arquivo em binário
                    with open(filename, "rb") as f:
                        while True:
                            chunk = f.read(4096)
                            if not chunk:
                                break
                            s.sendall(chunk)
                            bytes_sent += len(chunk)

                    # aguardar confirmação
                    resp = recvline(s)
                    if resp:
                        bytes_recv += len(resp.encode())
                    print("[i] servidor:", resp)

                elif cmd.lower() == "quit":
                    bye = recvline(s)
                    if bye:
                        bytes_recv += len(bye.encode())
                        print("[i] servidor:", bye)
                    break

                else:
                    # para comandos inválidos: servidor responde com linha
                    resp = recvline(s)
                    if not resp:
                        print("[!] conexão fechada pelo servidor")
                        break
                    bytes_recv += len(resp.encode())
                    print("[i] servidor:", resp)

    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário.")
    except Exception as e:
        print(f"[!] Erro de rede: {e}")
    finally:
        end_time = time.time()
        # parar coleta TCP_INFO
        if tcpinfo_thread:
            tcpinfo_stop.set()
            tcpinfo_thread.join(timeout=1)

        # parar capture
        stop_packet_capture(capture_proc)

        # escrever log por conexão (arquivo)
        log_connection_file(logfile, start_time, end_time, bytes_sent, bytes_recv, tcp_info_records if tcp_info_records else None)
        print(f"[+] Log salvo em {logfile}")
        if args.capture and os.path.exists(pcapfile):
            print(f"[+] Pcap salvo em {pcapfile} (abra com Wireshark/tshark).")
        elif args.capture:
            print("[!] pcap não gerado.")

if __name__ == "__main__":
    main()
