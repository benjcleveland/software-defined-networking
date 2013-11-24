#!/usr/bin/env python

from pox.core import core
from pox.lib.revent import *
from pox.lib.packet.arp import arp
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ethernet import ETHER_BROADCAST

from learning_switch import learningswitch

log = core.getLogger()

class nat(EventMixin):
    def __init__(self, connection):
        # add the nat to this switch
        self.connection = connection
        self.listenTo(connection)
        self.eth2_ip = IPAddr('172.64.3.1')
        self.eth1_ip = IPAddr('10.0.1.1')

        # todo - this only works in carp...
        self.mac = connection.eth_addr 
        print self.mac

        self.outmac = connection.ports[4].hw_addr

        self.arp_table = {} # ip to mac,port
        self.port_map = {} # port -> ip, port

        #todo...
        self.send_arp(IPAddr('172.64.3.21'))
        self.send_arp(IPAddr('172.64.3.22'))


    def send_arp(self, host):
        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = host
        r.hwsrc = self.mac
        r.protosrc = self.eth2_ip
        e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        
        log.debug("Sending ARP request for %s", host)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        # todo remove hard coded port
        msg.actions.append(of.ofp_action_output(port = 4))
        msg.in_port = of.OFPP_NONE
        self.connection.send(msg)

    def map_port(self, tcp):
        '''
        return a port to map this connection to 
        '''
        # todo - this need to be a lot better...
        return tcp.srcport + 1000

    def handle_arp(self, event, packet):
        '''
        handle arp replies
        '''
        arp_req = packet.next
        if arp_req.opcode == arp.REPLY and arp_req.hwdst == self.mac:
            log.debug("updating arp table for %s" % arp_req.protosrc)
            self.arp_table[arp_req.protosrc] = (packet.src, event.port)


    def _handle_PacketIn(self, event):
        '''
        handle packets that are sent to the controller
        '''

        # parse the input packet
        packet = event.parse()

        # handle arp
        if isinstance(packet.next, arp):
            return self.handle_arp(event, packet)

        log.debug("received packet %s %s %s %s" % (str(packet.src), str(packet.dst), str(event.port), str(packet.next)))

        tcp = packet.find('tcp')
        if tcp:
            self.arp_table[packet.find('ipv4').srcip] = (packet.src, event.port)

            # we got a tcp packet!
            log.debug("received a tcp packet! %s" % tcp)
            if event.port != 4: # and tcp.SYN == True
                log.debug("receive a SYN packet!!")
                port = self.map_port(tcp)
                self.port_map[port] = (packet.find('ipv4').srcip, tcp.srcport)
                log.debug("using port %s" % port)

                # change the source ip and port of this packet
                #tcp.srcport = port
    
                #msg = of.ofp_packet_out()
                msg = of.ofp_flow_mod()
                msg.data = event.ofp
                msg.in_port = event.port
                
                #msg.match = of.ofp_match.from_packet(packet)
                msg.match.nw_proto = 6
                msg.match.dl_type = 0x800
                msg.match.in_port = event.port
                msg.match.tp_src = tcp.srcport
                msg.match.dl_src = packet.src
                msg.match.nw_src = packet.find('ipv4').srcip
                print "dstination",packet.dst

                msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_table[packet.find('ipv4').dstip][0]))
                msg.actions.append(of.ofp_action_dl_addr.set_src(self.outmac))
                msg.actions.append(of.ofp_action_nw_addr.set_src(self.eth2_ip))
                msg.actions.append(of.ofp_action_tp_port.set_src(port))
                # update the destination mac based on the IP?
                msg.actions.append(of.ofp_action_output(port = 4))
                print msg
                self.connection.send(msg)

            elif event.port == 4:
                log.debug("creating flow from outside in!")
                print self.port_map, self.arp_table, tcp.seq
                # setup a flow in the other direction
                ip, ip_port = self.port_map[tcp.dstport]
                mac, port = self.arp_table[ip]

                msg = of.ofp_flow_mod()
                #msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = event.port

                msg.match.nw_proto = 6
                msg.match.in_port = event.port
                msg.match.dl_src = packet.src
                msg.match.tp_src = tcp.srcport
                msg.match.tp_dst = tcp.dstport
                msg.match.dl_type = 0x800
                msg.match.nw_src = packet.find('ipv4').srcip
                #msg.match.nw_src = 

                #msg.match = of.ofp_match.from_packet(packet)
                #msg.actions.append(of.ofp_action_dl_addr.set_src(self.mac))
                #msg.actions.append(of.ofp_action_nw_addr.set_src(self.eth1_ip))
                msg.actions.append(of.ofp_action_tp_port.set_dst(ip_port))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
                msg.actions.append(of.ofp_action_nw_addr.set_dst(ip))
                # update the destination mac based on the IP?
                msg.actions.append(of.ofp_action_output(port = port))
                print msg
                self.connection.send(msg)
                 

        # ignore UDP messages....

class nat_starter(EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection))
        if event.connection.dpid != 1:
            log.debug("Starting nat on %s" % (event.connection))
            nat(event.connection)
        else:
            log.debug("Starting learning switch on %s" % (event.connection))
            learningswitch.LearningSwitch(event.connection)

def launch():
    # start the nat
    core.registerNew(nat_starter)
