#!/usr/bin/env python

from pox.core import core
from pox.lib.revent import *
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr

from learning_switch import learningswitch

log = core.getLogger()

class nat(EventMixin):
    def __init__(self, connection):
        # add the nat to this switch
        self.connection = connection
        self.listenTo(connection)
        self.eth2 = IPAddr('172.64.3.1')
        # todo - this only works in carp...
        self.mac = connection.eth_addr 
        print self.mac

        #todo...

    def map_port(self, tcp):
        '''
        return a port to map this connection to 
        '''
        # todo - this need to be a lot better...
        return tcp.srcport + 1000

    def _handle_PacketIn(self, event):
        '''
        handle packets that are sent to the controller
        '''

        # parse the input packet
        packet = event.parse()

        #log.debug("received packet %s %s %s %s" % (str(packet.src), str(packet.dst), str(event.port), str(packet.next)))

        tcp = packet.find('tcp')
        if tcp:
            # we got a tcp packet!
            log.debug("received a tcp packet! %s" % tcp)
            if tcp.SYN == True:
                log.debug("receive a SYN packet!!")
                port = self.map_port(tcp)
                log.debug("using port %s" % port)

                # change the source ip and port of this packet
                tcp.srcport = port
    
                msg = of.ofp_packet_out()
                msg.data = event.ofp.data
                msg.in_port = event.port
                msg.actions.append(of.ofp_action_dl_addr.set_src(self.mac))
                msg.actions.append(of.ofp_action_nw_addr.set_src(self.eth2))
                msg.actions.append(of.ofp_action_tp_port.set_src(port))
                msg.actions.append(of.ofp_action_output(port = 4))
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
