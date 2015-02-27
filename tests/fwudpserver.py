#!/usr/bin/env python
import socket
import sys
import subprocess

print("Test server started.")

UDP_IP = "10.2.1.1"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))
#sock.bind(('', UDP_PORT))

outsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print("received message: %s"% data)
    try:
        req = data.split()
        request, fwCmd = req[0], " ".join(req[1:])
    except ValueError:
        print("value error")
        continue
    if request != "FWCMD":
        print("Not a firewall command from unit test request")
        continue
    print("Executing command: %s" % fwCmd)
    try:
        retcode = subprocess.call("%s" % fwCmd, shell=True)
        if retcode < 0:
            print >>sys.stderr, "Firewall command terminated by signal", -retcode
        else:
            print >>sys.stderr, "Command returned", retcode
    except OSError as e:
        print >>sys.stderr, "Execution failed:", e
    finally:
        print("send an ack back to %s, port %i" % (addr[0], 3457) )
        outsock.sendto("fwack", (addr[0], 3457))

outsock.close()
sock.close()


