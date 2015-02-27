#!/usr/bin/env python2
from scapy.all import sr1, send, sniff, UDP
import random
import socket, select
import inspect

DEFAULT_CONF = {"check":False,  # if True, check received packets using check
                                # function given as parameter in sendpkt call
                "debug":0,      # Levels 0-5. Greater means more verbose
                "printanswer":False,  
                "iptables_bin": "iptables", # iptables executable path
                "udp_port": 3456,
                }

# Exception class for PacketWaiting timeout handling
class PktWaitTimeOutException(Exception):
    def __init__(self, timeval):
        self.timeval = timeval
    def __str__(self):
        return repr(self.timeval)

class ProtoTester(object):
    """Main class of the core
    This defines the protocol-independent mechanism of the tester."""

    def __init__(self, conf=DEFAULT_CONF):
        # merge the config given in argument with the default one.
        self.conf = dict(DEFAULT_CONF.items() + conf.items())
        self.first = True
        # If True, allows kernel to see packets and interact with connection
        self.khandled = True 
        # proto related
        self.state = None
        self.proto = None

    def sendSequence(self, pktList, initstate=None, **kargs):
        """Send a sequence of packets with the synchronous sendpkt.
        The pktList is composed of classes of the protocol library.
        Returns a list of tuples (packetSent, validityOfReply, reply, state)""" 
        if "buffermode" in kargs:
            raise Exception("Buffermode cannot be used with sendSequence()")
        return [self.sendpkt(pkt, initstate, **kargs) for pkt in pktList]

        
    def sendpkt(self, newpkt, initstate=None, **kargs):
        """Generate and send a new packet
        
        Generate a new packet using the class newpkt, from existing current
        state overriden by initstate, then send it.
        Return a tuple (sent packet, validityOfReply, reply, new state)
        
        Arguments:
        newpkt -- class derived from ProtoLibPacket that represents the scapy packet to send.
        initstate -- state class (derived from ProtoState) overriding the current state. 
        kargs -- other optional arguments to be passed to the newpkt methods
        """
        # update the State
        if self.state is None:
            if initstate is None:
                # If no initial state is given at the first call, use a generic one
                self.state = ProtoState()
            else:
                self.state = initstate
        else:
            self.state.update(initstate)
        s = self.state # simple alias
        
        if self.first:
            self.first = False

        try:
            # generate the packet
            (pkt, wait) = newpkt().generate(s, **kargs)
        
            if s.hasKey("stage") and pkt is not None:
                self.debug("Generating %s packet..." % s["stage"], 1)
            # send the packet and possibly wait for the reply if wait is
            # defined by the generation
            r = self.run(s, pkt, wait)
            if type(r) is list: # buffermode
                return r
            # otherwise, it's a classic (validity, reply) tuple
            (ret, reply) = r

        except PktWaitTimeOutException as e:
            raise e
        except Exception as e:
            import sys
            if self.conf["debug"]:
                import traceback
                traceback.print_exc(file=sys.stdout)
            print("Error: %s" % e)
            print("Exiting.")
            sys.exit(0)
        
        return (pkt, ret, reply, self.state)


    def run(self, state, pkt, wait):
        """Send pkt, receive the answer if wait is defined, and return a tuple 
        (validity of reply packet, reply packet).
        
        pkt -- is a scapy representation of a packet. It can be None.
        wait -- If defined, it can either be a boolean, or a function 
        describing how to wait for a packet, or a tuple (function,
        maxTimeToWait, activationOfBufferMode)
        
        Returns a (validityOfReply, replyPacket) tuple"""

        self.dbgshow(pkt)
        if wait: # do we wait for a reply ?
            if pkt is None:
                self.debug("Waiting for packet...", level=1)
                timeout, buffermode = None, False
                if type(wait) is tuple:
                    wait, timeout, buffermode = wait
                if hasattr(wait, '__call__'):
                    ans = self.waitForPacket(filterfct=wait, timeout=timeout,
                            buffermode=buffermode)
                    if buffermode: # ans is a buffer (list)
                        self.debug("Entering buffer mode.", level=1)
                        return [self.packetReceived(pkt,buffermode=True) for pkt in ans]
                else:
                    raise Exception("error, no packet generated.")
            else:
                # when no wait function is specified, use the original scapy sender and
                # receiver.
                ans=sr1(pkt)
        else:
            # send the packet without waiting any reply.
            send(pkt)
            self.first = True # prev_pkt shouldnt be taken into account
            self.debug("Packet sent, no waiting, going on with next.",2)
            return (True, None) # no reply, no check
        return self.packetReceived(ans) # callback for received reply

    def waitForPacket(self, state=None, filterfct=None, timeout=None,
            buffermode=False, **kargs):
        """Wait for one packet matching a filter function

        filterfct -- boolean function applied on a packet received to select it
            or not. Ex: lambda pkt: pkt.haslayer("TCP")
        buffermode -- If True, stores until a UDP packet is received, then
            treat them all. Allows to receive several packets without dropping
            any due to synchronicity.
        other args: extra args for sniff function of scapy"""

        if state is None:
            if self.state is None:
                raise Exception("A state object must be given as parameter when \
                    waiting for a packet if no initstate entered in the Tester.")
            state = self.state
        else:
            self.state.update(state)
        if timeout:
            tOut = " (timeout after %i secs)" % timeout
        else: tOut = ""
        self.debug("Sniffing using custom function..."+tOut, level=2)
        if buffermode:
            # in buffermode, the packets are stored in buf and they are transmitted
            # to user only when a UDP signal is encountered
            buf = sniff(count=0, lfilter=lambda pkt: filterfct(pkt) or \
                    pkt.haslayer(UDP), filter="udp or tcp",
                    stop_filter=lambda pkt: pkt.haslayer(UDP),
                    timeout=timeout, **kargs)
            # acknowledge the UDP signal
            self.sendAck(buf[-1].getlayer("IP").src)
            return buf[:-1]
        
        # wait for a single packet matching the filterfct requirement
        pkts = sniff(count=1, lfilter=filterfct, filter="tcp",
                    timeout=timeout, **kargs)
        # notify caller of a timeout
        if pkts is None or len(pkts) == 0:
            raise PktWaitTimeOutException(timeout)
        return pkts[0].getlayer("IP")


    def packetReceived(self, pkt, buffermode=False):
        """Called when a packet pkt is received, returns the packet and its
        supposed validity expressed as a boolean. This updates the state
        according to the recv() method of the packet received."""
        initstate = self.state.copy()
        self.printrcvd(pkt)
        self.state.logPacket(pkt)
        pktTest = None
        # Retrieve the components class to handle in a receivd packet
        finder = self.proto.findProtoLayer(pkt)
        self.debug("Packets components to handle: %s" % [a for a in finder], 4)
        finder = self.proto.findProtoLayer(pkt)
        if not finder:
            return (False, pkt)
        # loop on the components, ensure that they are bound to a
        # ProtoLibPacket class, if not, ask the proto to recognize it and
        # return the corresponding ProtoLibPacket class.
        for p in finder:
            if "recv" in dir(p):
                pktTest = p
            else:
                pktTest = self.proto.getClassFromPkt(p, pkt)()
            valid = self.checkRcvd(initstate, pkt, pktTest)
            if not valid:
                return (False, pkt)
            # update the state according to packet received
            needReply = pktTest.recv(self.state, pkt)
            if needReply and buffermode: 
                # useful for acks: in buffermode (or data receiving mode), the
                # remote host expects acks that must be generated according to
                # the data received. Only an ACK would be enough, but send one
                # for each anyway.
                self.sendpkt(needReply)
        return (True, pkt)

    def checkRcvd(self, init, pkt, pktTest):
        """Test the validity of a received packet according to previous
        state"""
        if self.conf["check"] is False:
            return True
        
        if not pktTest.check(init,pkt):
            print("Test failed: %s", ret);
            return False
        return True

    # Optional Debug / Print
    def printrcvd(self, pkt):
        if self.conf["printanswer"] or self.conf["debug"] >= 4:
            print("------ RECEIVED -------")
            pkt.show2()
            print("---- END of PACKET ----")
    
    def debug(self, str, level=3):
        if self.conf["debug"] >= level:
            frame,filename,line_number,function_name,lines,index=\
                    inspect.getouterframes(inspect.currentframe())[1]
            print("[%i:%s] %s"%(line_number,function_name,str))

    def dbgshow(self, pkt):
        if self.conf["debug"] >= 5:
            if not pkt:
                print "No packet to send."
                return
            print("------- TO SEND -------")
            pkt.show2()
            print("---- END of PACKET ----")

    

    def toggleKernelHandling(self, enable=None):
        """Toggle the kernel handling of the packets received. If enabled,
        the kernel will see packets and manage the connections, which isn't
        desirable while sending forged packets"""
        import os
        if enable is True or self.khandled is False:
            os.system("%s -D INPUT -p tcp -j DROP" % self.conf["iptables_bin"])
            self.khandled = True
        elif enable is False or self.khandled is True:
            os.system("%s -A INPUT -p tcp -j DROP" % self.conf["iptables_bin"])
            self.khandled = False

    # For purpose of communication with the other test instance.
    def sendState(self, state=None, dst=None):
        """Send state in its network representation to dst, using UDP"""
        if dst is None and state and state.hasKey("dst"):
            dst = state["dst"]
        elif dst is None:
            raise Exception("no destination found for sending state")
        if state is None:
            data = "unit"
        else:
            data = state.toNetwork()
        self.debug("UDP signal sent to %s: %s" % (dst,data), 5)
        outsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        outsock.sendto(data, (dst, self.conf["udp_port"]))
        sock.bind(('', self.conf["udp_port"])) # wait for ack
        while not select.select([sock], [], [],0.1)[0]:
            outsock.sendto(data, (dst, self.conf["udp_port"]))
        sock.recvfrom(10)
        sock.close()
        outsock.close()
        
    def receiveState(self, cls=None, src=None, bindTo=''):
        """Wait to receive state in its network representation from src, using UDP
        Return the state as a dictionary"""
        sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((bindTo, self.conf["udp_port"]))
        data, addr = sock.recvfrom( 2048 )
        self.debug("Received data from %s: '%s'"%(addr,data))
        while src is not None and addr[0] != src:
            data, addr = sock.recvfrom( 2048 )
            self.debug("Received data from %s: '%s'"%(addr,data))
        sock.close()
        self.sendAck(addr[0])
        if cls is None: return # for sync purposes, give up data
        return cls.fromNetwork(data)

    def sendAck(self,addr):
        """Send an UDP acknowledgment to ensure synchronization of tester
        instances"""
        outsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        outsock.sendto("ack", (addr, self.conf["udp_port"]))
        outsock.close()

class ProtoLibPacket(object):
    """Represents the actions applyable to a packet type. The packet specified
    for sending must use a derived class (or one that implements) of this one."""
    def generate(self, state):
        """Describe the packet to send for the class's packet type""" 
        pass
    def recv(self, state, pkt):
        """Parse the packet and alter the state according to the class's packet type"""
        pass
    def check(self, state, pkt):
        """Check a received packet given an initial state
        Return a boolean"""
        return True


class ProtoState(object):
    """Abstract class.
    This represents the state of a protocol. Protocol libraries should use
    this as a base class for use with this test engine"""
    def __init__(self, initstate={},conf=DEFAULT_CONF):
        # the internal state is implemented with a dictionary d.
        self.d = {}
        self.initAttr()
        self.update(initstate)
        self.conf = conf

    def initAttr(self):
        """Populate the internal dictionary with default values."""
        pass
    
    def debug(self, str, level=3):
        if self.conf["debug"] >= level:
            print("[%s] %s"%(self.name,str))

    def __getitem__(self, attr):
        return self.d[attr]

    def __setitem__(self, attr, val):
        # called for modifying a state value. Also useful for debugging.
        if attr in ["ack", "seq"]:
            self.debug("%s: %i --> %i"% (attr, self.d[attr],val), level=5)
            self.debug(inspect.stack(), level=5)
        if attr in ["map"]:
            self.debug("%s: %s --> %s" % (attr, self.d[attr],val), level=4)
        if attr in ["dsn", "data_ack"]:
            self.debug("%s: %i --> %i" % (attr, self.d[attr],val), level=3)
            self.debug(inspect.stack(), level=5)
        self.d[attr] = val

    def toNetwork(self):
        return str(self.d)

    @classmethod
    def fromNetwork(cls, dictstr):
        import ast
        return ast.literal_eval(dictstr)

    def update(self, extrastate):
        """Update the current state with the extrastate. Extrastate must be a
        ProtoState derivative"""
        if extrastate is not None:
            if type(extrastate) is dict:
                e = extrastate.items()
            else:
                e = extrastate.d.items()
            self.d = dict(self.d.items() + e)
        return self
        
    def hasKey(self, key):
        return key in self.d.keys()

    def copy(self):
        import copy
        return copy.deepcopy(self)

    def logPacket(self, pkt):
        self.d["prev_pkt"] = pkt

    def getLastPacket(self):
        if "prev_pkt" in self.d.keys():
            return self.d["prev_pkt"]
        else:
            return None

    
# useful functions in the context of protocol testing
def xlong(s):
    """Convert a string into a long integer"""
    l = len(s)-1
    return sum([ord(c) << (l-e)*8 for e,c in enumerate(s)])

def xstr(x):
    """Convert an integer into a string"""
    return xstr(x >> 8) + chr(x&255) if x else ''

def randintb(n):
    """Picks a n-bits value at random"""
    return random.randrange(0, 1L<<n)

# vim: set ts=4 sts=4 sw=4 et:
