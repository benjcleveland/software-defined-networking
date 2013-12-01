#!/usr/bin/env python
'''
Ben Cleveland
CSEP 561
Project 3
NAT
'''

from pox.core import core
from pox.lib.revent import *
from pox.lib.packet.arp import arp
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ethernet import ETHER_BROADCAST

from learning_switch import learningswitch

import time

log = core.getLogger()

# TCP timeouts in seconds
#TCP_ESTABLISHED_TIMEOUT = 7440
#TCP_TRANSITORY_TIMEOUT = 300
TCP_ESTABLISHED_TIMEOUT = 70
TCP_TRANSITORY_TIMEOUT = 3

ARP_TIMEOUT = 2000

# states
ESTABLISHED = 'established'
SYN_SENT = 'syn_sent'
SIMULTANEOUS_OPEN = 'sim open!'
SYN_ACK_RECV = 'syn ack recv'
CONNECTING = 'connecting'
CLOSING = 'closing'

EXTERNAL_IP = '172.64.3.0/24'
INTERNAL_IP = '10.0.1.0/24'

class connection():
    def __init__(self, ip, port, dstport, state=SYN_SENT):
        self.port = port
        self.ip = ip
        self.dstport = dstport
        self.state = state
        self.client_fin = False
        self.server_fin = False
        self.last_time = time.time()
        self.num_flows = 0

    def __str__(self):
        return str(self.ip) + ':' + str(self.port)

    def touch(self):
        self.last_time = time.time()

class natmap():
    ''' 
    class containing information about a connection
    '''

    def __init__(self):
        self.port_map = {} # nat port -> client ip, port
        self.rev_map = {} # client ip, port - > nat port
        return
    
    def add(self, con):
        '''
        add a connection to track
        '''
        self.port_map[con.dstport] = con
        self.rev_map[str(con)] = con.dstport

    def remove(self, con):
        del self.port_map[con.dstport]
        del self.rev_map[str(con)]
        return

    def getCon(self, port):
        return self.port_map.get(port, None) 

    def getConIp(self, client_ip, port):
        print self.rev_map
        ipport = str(client_ip) + ':' + str(port)
        ret = self.rev_map.get(ipport, None)
        if ret != None:
            ret = self.port_map.get(ret, None)
        return ret
    
    def getPorts(self):
        return self.rev_map.values()

    def __iter__(self):
        return self.port_map.iteritems()

class nat(EventMixin):
    def __init__(self, connection):
        # add the nat to this switch
        self.connection = connection
        self.listenTo(connection)
        self.eth2_ip = IPAddr('172.64.3.1')
        self.eth1_ip = IPAddr('10.0.1.1')

        self.outmac = connection.ports[4].hw_addr

        self.arp_table = {} # ip to mac,port
        self.natmap = natmap()
        
        #todo...
        self.send_arp(IPAddr('172.64.3.21'))
        self.send_arp(IPAddr('172.64.3.22'))

        #core.callDelayed(1, self.cleanupConnections)

    def cleanupConnections(self):
        '''
        periodically cleanup connections that have timed out
        '''
        log.debug("running cleanup connections!!")
        remove = []
        for port, con in self.natmap:
            if con.state != ESTABLISHED:
                if con.last_time + TCP_TRANSITORY_TIMEOUT < time.time():
                    log.debug("removing connection, transitory timeout")
                    remove.append(con)

        for con in remove:
            log.debug("really removing the connection!!")
            self.natmap.remove(con)
        core.callDelayed(1, self.cleanupConnections)

    def send_arp(self, host):
        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = host
        r.hwsrc = self.outmac
        r.protosrc = self.eth2_ip
        e = ethernet(type=ethernet.ARP_TYPE, src=self.outmac,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        
        log.debug("Sending ARP request for %s", host)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        # todo remove hard coded port
        msg.actions.append(of.ofp_action_output(port = 4))
        msg.in_port = of.OFPP_NONE
        self.connection.send(msg)

    def handle_arp(self, event, packet):
        '''
        handle arp replies
        '''
        arp_req = packet.next
        if arp_req.prototype == arp.PROTO_TYPE_IP and arp_req.hwtype == arp.HW_TYPE_ETHERNET and arp_req.protosrc != 0:
            log.debug("ARP proto source..." + str(arp_req.protosrc) + str(arp_req.protodst))

            if arp_req.opcode == arp.REPLY and arp_req.hwdst == self.outmac:
                log.debug("updating arp table for %s" % arp_req.protosrc)
                self.arp_table[arp_req.protosrc] = (packet.src, event.port, time.time() * ARP_TIMEOUT)
                return

            # update the arp table
            self.arp_table[arp_req.protosrc] = (packet.src, event.port, time.time() * ARP_TIMEOUT)

            # see if we can handle the arp request (we know the dst and it hasn't expired)
            if arp_req.opcode == arp.REQUEST:
                if arp_req.protodst in self.arp_table and self.arp_table[arp_req.protodst][2] > time.time():
                    # we can respond to the ARP request
                    log.debug("responding to ARP request...")

                    # create the arp response packet
                    arp_res = arp()
                    arp_res.hwtype = arp_req.hwtype
                    arp_res.prototype = arp_req.prototype
                    arp_res.hwlen = arp_req.hwlen
                    arp_res.protolen = arp_req.protolen
                    arp_res.opcode = arp.REPLY
                    arp_res.hwdst = arp_req.hwsrc
                    arp_res.protodst = arp_req.protosrc
                    arp_res.protosrc = arp_req.protodst
                    arp_res.hwsrc = self.arp_table[arp_req.protodst][1]

                    # create an ethernet package that contains the arp response we created above
                    e = ethernet(type=packet.type, src=self.outmac, dst=arp_req.hwsrc)
                    e.set_payload(arp_res)
                    log.debug("%i %i answering ARP for %s" % (event.connection.dpid, event.port, str(arp_res.protosrc)))

                    # send the ARP response
                    msg = of.ofp_packet_out()
                    msg.data = e.pack()
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                    msg.in_port = event.port
                    event.connection.send(msg)
                    return

                elif arp_req.protodst == IPAddr('10.0.1.1'):
                    # handle client side
                    # create the arp response packet
                    self.send_arpResponse(arp_req, event, packet, self.connection.ports[event.port].hw_addr)
                    return
                elif arp_req.protodst == IPAddr('172.64.3.1'):
                    # handle server side
                    log.debug("repsonding to arp for server ip, %s" % event.port)
                    self.send_arpResponse(arp_req, event, packet, self.connection.ports[event.port].hw_addr)
                    return

        # we don't know where this mac is, flood the packet
        if event.port == 4:
            log.debug("flooding ARP packet!" + str(self.arp_table))
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)
        else:
            log.debug("flooding client arp packet")
            msg = of.ofp_packet_out()
            for i in range(0,4):
                msg.actions.append(of.ofp_action_output(port = i ))
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)
        return 

    def send_arpResponse(self, arp_req, event, packet, mac):
        # create the arp response packet
        arp_res = arp()
        arp_res.hwtype = arp_req.hwtype
        arp_res.prototype = arp_req.prototype
        arp_res.hwlen = arp_req.hwlen
        arp_res.protolen = arp_req.protolen
        arp_res.opcode = arp.REPLY
        arp_res.hwdst = arp_req.hwsrc
        arp_res.protodst = arp_req.protosrc
        arp_res.protosrc = arp_req.protodst
        arp_res.hwsrc = mac

        # create an ethernet package that contains the arp response we created above
        e = ethernet(type=packet.type, src=mac, dst=arp_req.hwsrc)
        e.set_payload(arp_res)
        log.debug("%i %i answering ARP for %s" % (event.connection.dpid, event.port, str(arp_res.protosrc)))

        # send the ARP response
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)

    def send_packet(self, event, dstip, con, out_dir=True):
        ''' 
        sends a packet out of the nat
        '''
        msg = of.ofp_packet_out()
        #msg.buffer_id = None
        msg.data = event.ofp
        msg.in_port = event.port
        
        if out_dir == True:
            msg.actions = self.get_out_actions(con, dstip)
        else:
            msg.actions = self.get_in_actions(con)

        print msg
        self.connection.send(msg)

    def get_out_actions(self, con, dstip):
        actions = []
        actions.append(of.ofp_action_dl_addr.set_src(self.outmac))
        actions.append(of.ofp_action_nw_addr.set_src(self.eth2_ip))
        actions.append(of.ofp_action_tp_port.set_src(con.dstport))
        actions.append(of.ofp_action_dl_addr.set_dst(self.arp_table[dstip][0]))
        actions.append(of.ofp_action_output(port = 4))

        return actions
    def get_in_actions(self, con):
        actions = []
        # actions for coming in
        mac, port, mytime = self.arp_table[con.ip]

        actions.append(of.ofp_action_dl_addr.set_dst(mac))
        actions.append(of.ofp_action_nw_addr.set_dst(con.ip))
        actions.append(of.ofp_action_tp_port.set_dst(con.port))
        actions.append(of.ofp_action_output(port = port))
        return actions
        
    def create_flow(self, event, packet, tcp, ip, con, data=None, out_dir=True):
        '''
        create a new flow
        '''
        flow = of.ofp_flow_mod()

        if data != None:
            flow.data = data
            flow.buffer_id = None
            flow.in_port = event.port

        flow.match.nw_proto = 6
        flow.match.dl_type = ethernet.IP_TYPE

        # set the timeout value
        flow.idle_timeout = TCP_ESTABLISHED_TIMEOUT
        flow.flags |= of.OFPFF_SEND_FLOW_REM
        flow.flags |= of.OFPFF_CHECK_OVERLAP

        if out_dir == True:
            #flow.match = of.ofp_match.from_packet(packet)
            flow.match.in_port = event.port
            flow.match.tp_src = tcp.srcport
            #flow.match.dl_src = packet.src
            flow.match.nw_src = ip.srcip

            # actions for going out
            flow.actions = self.get_out_actions(con, ip.dstip)
        else:
            flow.match.in_port = 4
            #flow.match.tp_src = tcp.dstport
            flow.match.tp_dst = con.dstport
            #flow.match.dl_src = src_mac
            #flow.match.nw_src = ip.dstip
            flow.match.nw_dst = self.eth2_ip

            # actions for coming in
            flow.actions = self.get_in_actions(con)

        print flow
        log.debug("creating out flow, %s" % event.port)
        self.connection.send(flow)

    def create_in_flow2(self, event, packet, tcp, ip, con):
        flow = of.ofp_flow_mod()
        flow.data = event.ofp
        flow.buffer_id = event.ofp.buffer_id
        #flow.in_port = event.port

        flow.match.nw_proto = 6
        flow.match.dl_type = 0x0800
        flow.match.in_port = 4
        #flow.match.tp_src = tcp.srcport
        flow.match.tp_dst = tcp.dstport
        #flow.match.dl_src = packet.src
        #flow.match.nw_src = ip.srcip
        flow.match.nw_dst = self.eth2_ip

        # set the timeout value
        flow.idle_timeout = TCP_ESTABLISHED_TIMEOUT
        flow.flags |= of.OFPFF_SEND_FLOW_REM
        flow.flags |= of.OFPFF_CHECK_OVERLAP

        mac, port, mytime = self.arp_table[con.ip]

        flow.actions.append(of.ofp_action_nw_addr.set_dst(con.ip))
        flow.actions.append(of.ofp_action_tp_port.set_dst(con.port))
        flow.actions.append(of.ofp_action_dl_addr.set_dst(mac))
        flow.actions.append(of.ofp_action_output(port = port))

        print flow
        self.connection.send(flow)

    def map_port(self, port):
        '''
        return a port to map this connection to 
        '''
        used_ports = self.natmap.getPorts()

        dstport = port + 1
        if dstport < 1024 or dstport >= 65534:
            dstport = 1024

        for count in range(0,2):
            if dstport not in used_ports:
                return dstport
            dstport += 1
            if dstport >= 65534:
                dstport = 1024

        return None

    def nat_packet(self, event, packet, tcp, ip):
        # we got a tcp packet!
        log.debug("received a tcp packet! %s %s" % (ip, tcp))

        # from inside
        if event.port != 4 and ip.dstip.inNetwork(EXTERNAL_IP):
            # see if a connection already exists or not
            con = self.natmap.getConIp(ip.srcip, tcp.srcport)
            if con == None:
                # can we create a new connection?
                # yes (syn from client) or ?
                if tcp.SYN == True and tcp.ACK == False:
                    # create a new connection
                    dstport = self.map_port(tcp.srcport)
                    if dstport == None:
                        log.error("Out of port mappings to used... dropping packet")
                        return
                    con = connection(ip.srcip, tcp.srcport, dstport)
                    self.natmap.add(con)
                    log.debug("creating a new connection %s %s %s" % (ip.srcip, tcp.srcport, dstport))
                    time.sleep(1)
                    self.send_packet(event, ip.dstip, con)
                else: # no
                    # ignore this packet
                    log.debug("DROPPING PACKET AT START OF CONNECTION!!")
            else:  # connection exists
                log.debug("connection already exists, %s %s" % (con.state, event.port))
                # make sure the connection is in the correct state and we are
                # receiving the expected packet sequence
                if (con.state == SYN_ACK_RECV and tcp.ACK == True and tcp.SYN == False) or (con.state == SIMULTANEOUS_OPEN and tcp.ACK == True and tcp.SYN == True):
                        # update state     
                        con.num_flows += 2
                        # forward message
                        # TODO - create the flow for this connection 
                        # do this in both directions?
                        # a connection has been established - create a flow
                        con.touch()
                        log.debug("creating flow for connection!")

                        self.create_flow(event, packet, tcp, ip, con, out_dir=False)
                        self.create_flow(event, packet, tcp, ip, con, event.ofp)

                        con.state = ESTABLISHED
                        self.natmap.add(con)
                        log.debug("\n\n\n\n")
                        return
                elif con.state == ESTABLISHED:
                    log.debug("AHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
                    #return
                log.debug("sending packet out connection %s %s %s" % (ip.srcip, tcp.srcport, con.dstport))
                self.send_packet(event, ip.dstip, con)
                return
        elif ip.dstip == self.eth2_ip:# from outside
            # make sure this tcp packet is for us
            con = self.natmap.getCon(tcp.dstport)
            if con == None:
                # silently drop the packet since the connection doesn't exist yet...
                log.debug("No mapping for this packet from outside....")
                return
            else:
                if con.state == SYN_SENT or con.state == SIMULTANEOUS_OPEN:
                    if tcp.SYN == True and tcp.ACK == False:
                        # support simultaneous open
                        con.state = SIMULTANEOUS_OPEN
                        
                    if tcp.SYN == True and tcp.ACK == True:
                        if con.state != SIMULTANEOUS_OPEN:
                            con.state = SYN_ACK_RECV

                    # send out the packet
                    log.debug("sending server packet...")

                    con.touch()
                    self.natmap.add(con)
                    mac, port, mytime = self.arp_table[con.ip]
                    self.send_packet(event, con.ip, con, out_dir = False)
                    log.debug("syn packet")
                    return

                else:

                    mac, port, mytime = self.arp_table[con.ip]
                    self.send_packet(event, con.ip, con, out_dir = False)
                    log.debug("syn packet")
                    log.debug("in unhandled state... %s" % con.state);    
                    return

    def _handle_PacketIn(self, event):
        '''
        handle packets that are sent to the controller
        '''
        # parse the input packet
        packet = event.parse()

        log.debug("received packet %s %s %s %s" % (str(packet.src), str(packet.dst), str(event.port), str(packet.next)))
        # handle arp
        if isinstance(packet.next, arp):
            return self.handle_arp(event, packet)

        ip = packet.find('ipv4')
        tcp = packet.find('tcp')

        if ip:
            # update the arp table
            self.arp_table[ip.srcip] = (packet.src, event.port, time.time() * ARP_TIMEOUT)

        if ip and ip.dstip.inNetwork('10.0.1.0/24') == True:
            # flood the message to the internal clients
            log.debug("flooding packet on client network")
            return self.flood_packet(event)

        if tcp and ip:
            # see if we can nat this packet
            return self.nat_packet(event, packet, tcp, ip)

        # ignore UDP and any other messages....

    def flood_packet(self, event):
        '''
        Flood the given event to just the client links
        '''
        msg = of.ofp_packet_out()
        for i in range(0,4):
            msg.actions.append(of.ofp_action_output(port = i ))
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    def _handle_FlowRemoved(self, event):
        '''
        handles removing the flow from the NAT when the 
        TCP Established timeout has been hit.
        '''
        log.debug("received flow removed event! %s" % dir(event.ofp))
        log.debug(event.ofp.show())
        match = event.ofp.match
        con = None
        if match.in_port != 4:
            # out going flow
            con = self.natmap.getConIp(match.nw_src, match.tp_src)
        else:
            con = self.natmap.getCon(match.tp_dst)

        if con != None:
            con.num_flows -= 1
            # if we can remove this connection
            if con.num_flows == 0:
                self.natmap.remove(con)
                log.debug("removed connection")
            else:
                self.natmap.add(con)

class nat_starter(EventMixin):

    def __init__(self, firewall):
        self.listenTo(core.openflow)
        self.firewall = firewall

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection))
        if event.connection.dpid != 1:
            log.debug("Starting nat on %s" % (event.connection))
            nat(event.connection)
        else:
            log.debug("Starting learning switch on %s" % (event.connection))
            learningswitch.LearningSwitch(event.connection)

    def _handle_PacketIn(self, event):
        ip = event.parsed.find('ipv4')
        print event, ip, self.firewall
        if self.firewall != None and ip and ip.dstip == IPAddr('172.64.3.22'):
            log.debug('dropping packet because of firewall')
            event.halt = True
            return 

def launch(firewall=None):
    # start the nat
    core.registerNew(nat_starter, firewall)
