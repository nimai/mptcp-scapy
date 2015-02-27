#!/usr/bin/env python2

from tests.mptcptestlib import *

def main():
    conf = {"printanswer":False, "debug":5, "check": False}
    t = ProtoTester(conf) # Core tester, protocol-agnostic.
    s = MPTCPState() # Connection, containing its state and methods to manipulate it
    m = MPTCPTest(tester=t, initstate=s) # MPTCP packets library
    
    # Client IPs
    A1 = "10.1.1.2"
    A2 = "10.1.2.2"
    # Server IP
    B = "10.2.1.2"
    # FW IP
    C = "10.2.1.1"

    
    # Block the packets before they are handled by the local network stack,
    # this permits to receive packets without any kernel interferences.
    t.toggleKernelHandling(enable=False)
    try:
        conn_accept = [m.Wait, m.CapSYNACK, m.Wait]
        # Then, we can execute that scenario part:
        t.sendSequence(conn_accept, initstate=s)#, sub=sub1)
        

        # Register a new subflow
        sub2 = s.registerNewSubflow(dst=A2, src=B)

        # test 1
        t.fwCmd("iptables -D FORWARD -d 10.1.0.0/16 -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", dst=C)
        t.fwCmd("iptables -A FORWARD -d 10.1.0.0/16 -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT", dst=C)
        t.sendpkt(m.JoinSYN, initstate=s, sub=sub2)
        
        t.syncWait()

        # test 2
        t.fwCmd("iptables -D FORWARD -p tcp -d 10.1.0.0/16 -m conntrack --ctstate ESTABLISHED -j ACCEPT", dst=C)
        t.fwCmd("iptables -A FORWARD -p tcp -d 10.1.0.0/16 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", dst=C)
        t.sendpkt(m.JoinSYN, initstate=s, sub=sub2)
        
        join_init = [m.Wait, m.JoinACK, m.Wait]
        t.sendSequence(join_init, initstate=s, sub=sub2)


        sub1 = s.getSubflow(0)

        t.syncReady(dst=A1)
        
        data_fin_seq = [m.Wait, m.DSSFINACK, m.Wait]
        t.sendSequence(data_fin_seq, sub=sub2)

        # synchronization with client to ensure no packet is lost
        #t.syncWait()

        # assuming that the remote host uses a single FINACK packet
        fin_init1 = [m.FIN, m.Wait, m.ACK]
        t.sendSequence(fin_init1, sub=sub1)

        #t.syncReady(dst=A1)
        fin_init2 = [m.Wait, m.FINACK, m.Wait]
        t.sendSequence(fin_init2, sub=sub2)

    finally:
        t.toggleKernelHandling(enable=True)

if __name__ == "__main__":
    main()

# vim: set ts=4 sts=4 sw=4 et:
