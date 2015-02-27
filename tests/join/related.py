#!/usr/bin/env python2
# Client part of the reference scenario
# See comments in scenario-server.py
from tests.mptcptestlib import *

def main():
    conf = {"printanswer":False, "debug":5, "check": False}
    t = ProtoTester(conf)
    s = MPTCPState()
    m = MPTCPTest(tester=t, initstate=s)

    # Client IPs
    A1 = "10.1.1.2"
    A2 = "10.1.2.2"
    # Server IP
    B = "10.2.1.2"

    dataisDropped = False
    data2isDropped = False

    t.toggleKernelHandling(enable=False)
    try:
        sub1 = s.registerNewSubflow(dst=B, src=A1)
        conn_open = [m.CapSYN, m.Wait, m.CapACK]
        t.sendSequence(conn_open, initstate=s, sub=sub1)

        # test 1, JOINSYN from B should be dropped
        try:
            t.sendpkt(m.Wait, timeout=1) 
        except PktWaitTimeOutException as e:
            print "No packet in last %i seconds"%e.timeval
            dataisDropped=True
        
        # test 2 with related rule
        # B is waiting before sending another join syn with the RELATED rule
        t.syncReady(dst=B)
        
        try:
            t.sendpkt(m.Wait, timeout=1) 
        except PktWaitTimeOutException as e:
            print "No packet in last %i seconds"%e.timeval
            data2isDropped=True

        join_accept = [m.JoinSYNACK, m.Wait, m.ACK] 
        t.sendSequence(join_accept, initstate=s)

        t.syncWait()
        
        sub2 = s.getSubflow(1)
        data_fin_init = [m.DSSFIN, m.Wait, m.DSSACK]
        t.sendSequence(data_fin_init, sub=sub2)

        #t.syncReady(dst=B)
        # assuming that the remote host uses a single FINACK packet
        fin_init1 = [m.Wait, m.FINACK, m.Wait]
        t.sendSequence(fin_init1, sub=sub1)

        #t.syncWait()
        fin_init2 = [m.FIN, m.Wait, m.ACK]
        t.sendSequence(fin_init2, sub=sub2)

        # computing test result
        ret = dataisDropped == True and data2isDropped == False
    finally:
        t.toggleKernelHandling(enable=True)

    import sys
    sys.exit(int(not ret))

if __name__ == "__main__":
    main()
# vim: set ts=4 sts=4 sw=4 et:
