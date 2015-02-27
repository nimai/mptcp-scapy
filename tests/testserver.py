#!/usr/bin/env python
import socket
import sys
import subprocess

print("Test server started.")

UDP_IP = "10.2.1.2"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print("received message: {}".format(data))
    try:
        (request, testScript) = data.split()
    except ValueError:
        continue
    if request != "EXECTEST":
        print("Not a unit test request")
        continue
    print("Executing unit test: {}".format(testScript))
    try:
        retcode = subprocess.call("server_%s" % testScript, shell=True)
        if retcode < 0:
            print >>sys.stderr, "Test was terminated by signal", -retcode
        else:
            print >>sys.stderr, "Test returned", retcode
    except OSError as e:
        print >>sys.stderr, "Test execution failed:", e



