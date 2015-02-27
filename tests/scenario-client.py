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

    t.toggleKernelHandling(enable=False)
    try:
        sub1 = s.registerNewSubflow(dst=B, src=A1)
        conn_open = [m.CapSYN, m.CapACK]
        t.sendSequence(conn_open, initstate=s, sub=sub1)

        t.sendState(dst=B) # useless synchronization

        join_accept = [m.Wait, m.JoinSYNACK, m.ACK] #final ack not necessary
                                                    #with old version of linux mptcp
        t.sendSequence(join_accept, initstate=s)
    
        m.send_data_sub(s, "Kikoolaba", sub=sub1)
        a = m.send_data(s,
                "Clientlatesraiunci,rnucieac,trseut,cerc,urteurc,surectsruc,steucesr,crsec,ucstrieucsr,ieusrt,uba")

        t.sendState(dst=B) # sync before final ack
        
        # wait for the ack of the last segment sent
        last = a[-1][0]
        t.sendpkt(m.Wait, waitfct=m.Wait.waitAckForPkt(s,last))
        
        sub2 = s.getSubflow(1)
        data_fin_init = [m.DSSFIN, m.DSSACK]
        t.sendSequence(data_fin_init, sub=sub2)

        t.sendState(dst=B)
        # assuming that the remote host uses a single FINACK packet
        fin_init1 = [m.FIN, m.ACK]
        t.sendSequence(fin_init1, sub=sub1)
        fin_init2 = [m.FIN, m.ACK]
        t.sendSequence(fin_init2, sub=sub2)
    finally:
        t.toggleKernelHandling(enable=True)

if __name__ == "__main__":
    main()
# vim: set ts=4 sts=4 sw=4 et:
