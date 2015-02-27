#!/usr/bin/env python2

from tests.mptcptestlib import *

def main():
    conf = {"printanswer":False, "debug":2, "check": False}
    t = ProtoTester(conf)
    s = MPTCPState(conf=conf)
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

        m.send_data(s, "ab")

        sub2 = s.registerNewSubflow(dst=B, src=A2)
        join_open = [m.JoinSYN, m.JoinACK]
        t.sendSequence(join_open, initstate=s, sub=sub2)
    
        m.send_data_sub(s,
        """Kikoolabaetaurnc,ric,etir,ucsreuetc.cnuece,unncenc,nucer,c
unret,cruiec,nurcter,rutnecrtnu,cnreuci,nreucrintiunr,ceunrt
unr,ceutnrceunrc,rntuectr,nucknre.ctnrucekt.rn""", sub=sub1)
        m.send_data(s,
                """KIKOOLABAETAURNC,RIC,ETIR,UCSREUETC.CNUECE,UNNCENC,NUCER,C
UNRET,CRUIEC,NURCTER,RUTNECRTNU,CNREUCI,NREUCRINTIUNR,CEUNRT
UNR,CEUTNRCEUNRC,RNTUECTR,NUCKNRE.CTNRUCEKT.RN""")
        m.send_data_sub(s,"cde", sub=sub2)
        
        t.sendpkt(m.DSSFIN, sub=sub1)
        t.sendpkt(m.DSSACK, sub=sub1)
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
