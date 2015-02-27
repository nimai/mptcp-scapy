#!/usr/bin/env python2
# See client counterpart for the test's explanations

from tests.mptcptestlib import *

def main():
    conf = {"printanswer":False, "debug":2, "check": False}
    t = ProtoTester(conf) # Core tester, protocol-agnostic.
    s = MPTCPState() # Connection, containing its state and methods to manipulate it
    m = MPTCPTest(tester=t, initstate=s) # MPTCP packets library
    
    # Client IPs
    A1 = "10.1.1.2"
    A2 = "10.1.2.2"
    # Server IP
    B = "10.2.1.2"

    droppedTimeout = 1
    
    # Block the packets before they are handled by the local network stack,
    # this permits to receive packets without any kernel interferences.
    t.toggleKernelHandling(enable=False)
    try:
        conn_accept = [m.Wait, m.CapSYNACK]
        t.sendSequence(conn_accept, initstate=s)#, sub=sub1)

        joinSYNisDropped = False
        try:
            t.sendpkt(m.Wait, timeout=droppedTimeout)
        except PktWaitTimeOutException as e:
            print "No packet in last %i seconds, considered dropped"%e.timeval
            joinSYNisDropped = True
        
        t.sendTestResult(("isDropped", joinSYNisDropped),dst=A1)
        sub1 = s.getSubflow(0)
        
        t.sendSequence([m.DSSFIN, m.Wait, m.DSSACK], sub=sub1)

        # synchronization with client to ensure no packet is lost
        t.syncReady(dst=A1)

        # assuming that the remote host uses a single FINACK packet
        fin_init1 = [m.Wait, m.FINACK, m.Wait]
        t.sendSequence(fin_init1, sub=sub1)
    finally:
        t.toggleKernelHandling(enable=True)

if __name__ == "__main__":
    main()

# vim: set ts=4 sts=4 sw=4 et:
