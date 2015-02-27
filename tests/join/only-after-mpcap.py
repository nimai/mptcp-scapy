#!/usr/bin/env python2
# This is a unit test, part of the mptcp firewall testing suite.
#
# Assertion verified: no mp_join packet is accepted by the firewall before the
# mp_capable handshake is successfuly terminated.
# 
# Setup: 
#   client ------MPCAP SYN-----> server
#          <--MPCAP SYNACK------ 
#          ------MPJOIN SYN----/ *
# Check: no packet received in a 1sec delay at *

from tests.mptcptestlib import *

def main():
    conf = {"printanswer":False, "debug":2, "check": False}
    t = ProtoTester(conf)
    s = MPTCPState()
    m = MPTCPTest(tester=t, initstate=s)

    # Client IPs
    A1 = "10.1.1.2"
    A2 = "10.1.2.2"
    # Server IP
    B = "10.2.1.2"

    result = False
    t.toggleKernelHandling(enable=False)
    try:
        sub1 = s.registerNewSubflow(dst=B, src=A1)
        conn_open = [m.CapSYN, m.Wait]
        t.sendSequence(conn_open, initstate=s, sub=sub1)

        sub2 = s.registerNewSubflow(dst=B, src=A2)
        early_join = [m.JoinSYN] 
        t.sendSequence(early_join, initstate=s, sub=sub2)

        result = t.getTestResult(src=B, 
                criterion=lambda x: x[0] == \
                        "isDropped" and x[1] == True)

        t.sendSequence([m.Wait, m.DSSFINACK, m.Wait], sub=sub1)

        t.syncWait()
        # assuming that the remote host uses a single FINACK packet
        fin_init1 = [m.FIN, m.Wait, m.ACK]
        t.sendSequence(fin_init1, sub=sub1)
    finally:
        t.toggleKernelHandling(enable=True)

    import sys
    # returns a zero value iff test has succeeded
    sys.exit(int(not result))

if __name__ == "__main__":
    main()
# vim: set ts=4 sts=4 sw=4 et:
