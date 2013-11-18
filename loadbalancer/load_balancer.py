'''
Ben Cleveland
CSEP 561
ben.j.cleveland@gmail.com

Project 2 - Load Balancer
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import IPAddr, EthAddr

from learning_switch import learningswitch

from random import randint, seed

log = core.getLogger()

# todo - add an arp and mac timeout
HARD_TIMEOUT = 360
IDLE_TIMEOUT = 1 # for easier debugging

ARP_TIMEOUT = 30 # timeout for entries in the ARP table

# todo - is there a better way to do this? get the mac address
def dpid_to_mac (dpid):
  '''
  get the mac address for this switch

  This code was taken from l3_learning.py in POX
  '''
  return EthAddr("%012x" % ((0xffff000000 | dpid) & 0xffFFffFFffFF,))


class LoadBalancer(EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    self.listenTo(connection)
    self.mac = {}
    
    self.data_ip = IPAddr('10.10.10.10')
    # list of IP addresses in the data system
    self.hosts = [IPAddr('10.0.0.2'), 
        IPAddr('10.0.0.3'),
        IPAddr('10.0.0.4'),
        IPAddr('10.0.0.5'),
        IPAddr('10.0.0.6'),
        IPAddr('10.0.0.7'),
        IPAddr('10.0.0.8'),
        IPAddr('10.0.0.9'),
        ]

    self.ip_port = {}
    self._all = False
    self.mymac = dpid_to_mac(self.connection.dpid)
    
    # seed the random number generator
    seed()

    print self.mymac
    # send out ARP requests for all the servers
    #if arp == True:
    #if self.connection.dpid == 9:
    core.callDelayed(1, self._send_arps)
    #self._send_arps()

  def _send_arps(self):
    '''
    Send out ARP requests to find the location of all the hosts
    '''
    for host in self.hosts:
        #time.sleep(1)
        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = host #server
        r.hwsrc = self.mymac
        r.protosrc = self.data_ip
        e = ethernet(type=ethernet.ARP_TYPE, src=self.mymac,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        
        #log.debug("Sending ARP request for %s", host)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = of.OFPP_NONE
        self.connection.send(msg)

    # run again at some delayed interval
    #core.callDelayed(100, self._send_arps)

  def send_arp_reply(self):
    '''
    Send out a reply with the given information
    '''
    return

  def handle_arp(self, event, packet):
    '''
    Handle the arp request if we can

    Note - this code was derived/inspired from the l3_learning.py switch in POX
    '''
    #log.debug("we got an ARP packet!!!" + str(event.connection.dpid))
   
    arp_req = packet.next
    if arp_req.opcode == arp.REPLY and arp_req.hwdst == self.mymac: # if this reply was meant for us
        if arp_req.protosrc not in self.ip_port:
            self.ip_port[arp_req.protosrc] = (event.port, packet.src)

        #if self.connection.dpid == 9:
        #    log.debug("updating ip to port table %s %s" % (self.ip_port, len(self.ip_port)))
        if len(self.hosts) == len(self.ip_port) and self._all == False:
            log.debug("I got them all!" + str(self.connection.dpid))
            self._all = True

            if self.connection.dpid == 6:
                log.debug("updating ip to port table %s %s %s" % (self.ip_port, len(self.ip_port), self.mac))
        return
    
    if arp_req.prototype == arp.PROTO_TYPE_IP and arp_req.hwtype == arp.HW_TYPE_ETHERNET and arp_req.protosrc != 0:

        if arp_req.opcode == arp.REQUEST and arp_req.protodst == self.data_ip:
            # respond to this arp from the client
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
            arp_res.hwsrc = self.mymac

            # create an ethernet package that contains the arp response we created above
            e = ethernet(type=packet.type, src=self.mymac, dst=arp_req.hwsrc)
            e.set_payload(arp_res)
            #log.debug("%i %i answering ARP for %s %s" % (event.connection.dpid, event.port, str(arp_res.protosrc), self.connection.eth_addr))

            # send the ARP response
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
            msg.in_port = event.port
            event.connection.send(msg)

            return
        
        if arp_req.hwsrc == self.mymac and arp_req.protodst in self.ip_port:
            #log.debug("loooop!!" + str(self.connection.dpid))
            # this arp is from us, and we already have the mac drop it...
            # it means that there is a loop somewhere in the network...
            #log.debug("dropping arp packet"  + str(arp_req.protosrc) + str(arp_req.protodst) + str(self.mymac) + str(self.connection.dpid))
            return

    if arp_req.REPLY and packet.dst in self.mac:
        #log.debug("sending to specific destination...")
        self.forward_packet(event, self.mac[packet.dst][0])
        return

    if arp_req.REQUEST and arp_req.protodst in self.ip_port and arp_req.protodst != self.data_ip:
        #log.debug("output to sending to specific destination..." + str(arp_req.protodst) +str(arp_req.hwsrc))
        self.forward_packet(event, self.ip_port[arp_req.protodst][0])
        return

    # we don't know where this mac is, flood the packet
    #log.debug("flooding arp packet..." + str(arp_req))
    self.flood_packet(event)
    return 

  def forward_packet(self, event, port):
    '''
    forwards the given packet out the given port
    '''
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = port))
    msg.data = event.ofp.data
    #msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)

  def flood_packet(self, event):
    '''
    Flood the given event to all links
    '''
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    #msg.buffer_id = event.ofp.buffer_id
    msg.data = event.ofp.data
    msg.in_port = event.port
    self.connection.send(msg)

  def add_flow(self, event, source, destination, dst_port, data = None, actions = None):
    '''
    Add a new flow from the source to the destination
    '''
    fm = of.ofp_flow_mod()
    fm.match.dl_dst = destination
    fm.match.dl_src = source
    fm.idle_timeout = IDLE_TIMEOUT
    fm.hard_timeout = HARD_TIMEOUT

    if data:
        # forward the packet to the destination
        fm.data = data
        fm.buffer_id = data.buffer_id

    if actions:
        fm.actions = actions

    fm.actions.append(of.ofp_action_output(port = dst_port))
    log.debug("installing a new flow for %s to %s.%i " % (source, destination, dst_port))
    self.connection.send(fm)

  def select_host(self, source):    
    '''
    select a host to start sending the data to
    '''
    #host = self.hosts[hash(ip.srcip) % len(self.hosts)]
    # select a random host
    host = self.hosts[randint(0, len(self.hosts)-1)]
    return host

  def _handle_PacketIn (self, event):
    '''
    handles new packages that are sent to the controller
    '''
    # parsing the input packet
    packet = event.parse()

    #log.debug("received packet %s %s %s %s" % (str(packet.src), str(packet.dst), str(event.port), str(packet.next)))

    # updating out mac to port mapping
    #if packet.src not in self.mac:
    #    #don't update the port if we already have it
    #    # TODO - make a list of possible ports
    #    self.mac[packet.src] = [event.port]
    #else:

    # TODO fix this - make it so you can have one copy of each
    self.mac[packet.src] = self.mac.get(packet.src,[]) + [event.port]
    #if packet.src not in self.mac:
    #    self.mac[packet.src] = [event.port]

    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      return

    # see if this is an ARP packet
    if isinstance(packet.next, arp):
        return self.handle_arp(event, packet)
    
    print packet.type
    ip = packet.find('ipv4')
    # if this is a TCP packet
    if ip:
        log.debug("got ip packet! %s %s" %(ip, self.connection.dpid))
        self.ip_port[ip.srcip] = (event.port, packet.src)
        # do we know this IP?
        if ip.dstip == self.data_ip:
            # determine the host to forward the packet too 
            host = self.select_host(ip.srcip)
            log.debug("%s woot %s %s" % (self.mymac, host, self.ip_port))

            # do we know how to get to this host?
            if host in self.ip_port:        
                # create a flow from this client to the host
                port, mac = self.ip_port[host]
                actions = []
                # change the dest mac and IP to match the host we picked
                actions.append(of.ofp_action_dl_addr.set_dst(mac))
                actions.append(of.ofp_action_nw_addr.set_dst(host))
                self.add_flow(event, packet.src, packet.dst, port, event.ofp, actions)
                return
            
        elif ip.srcip in self.hosts and ip.dstip not in self.hosts: # put a flow in the other direction changing the ip and mac
            log.debug("I don't know what to do with this packet" + str(self.connection.dpid))

            # create a flow from this client to the host
            port, mac = self.ip_port[ip.dstip]
            # change the src mac and IP to match that of the 'service'
            actions = []
            actions.append(of.ofp_action_dl_addr.set_src(self.mymac))
            actions.append(of.ofp_action_nw_addr.set_src(self.data_ip))
            self.add_flow(event, packet.src, packet.dst, port, event.ofp, actions)
            return

    # act like a normal switch if this is not going to our service IP address
    if packet.dst in self.mac:
        # normal switch stuff here...
        # TODO - handle the case where there are multiple paths
        log.debug("got past the ip stuff...")
        print self.ip_port
        # we know the destination port, install a flow table rule

        # TODO handle the case where the source and destination are the same...

        # make a flow in the other direction
        self.add_flow(event, packet.dst, packet.src, event.port)

        # create a new flow for this source and destination
        self.add_flow(event, packet.src, packet.dst, self.mac[packet.dst][randint(0, len(self.mac[packet.dst])-1)], event.ofp)
        return

    #log.debug("Port for %s unknown -- flooding" % (packet.dst,))
    # this should rarely occur...
    self.flood_packet(event)

class load_balancer(EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LoadBalancer(event.connection)

  #def _handle_PacketIn (self, event):
  #  print 'got packet event', event,event.connection

def launch ():
  #Starts an L2 learning switch.
  core.registerNew(load_balancer)
