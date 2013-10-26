'''
Ben Cleveland
CSEP 561

Learning Switch implementation with ARP handling
'''

"""
Author Junaid Khalid

This is an L2 learning switch written directly against the OpenFlow library.
It is derived from POX l2_learning.py only for IPv4.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import EthAddr

log = core.getLogger()

# todo - add an arp and mac timeout
HARD_TIMEOUT = 360
IDLE_TIMEOUT = 30

ARP_TIMEOUT = 360 # timeout for entries in the ARP table

# todo - is there a better way to do this? get the mac address
def dpid_to_mac (dpid):
  '''
  get the mac address for this switch

  This code was taken from l3_learning.py in POX
  '''
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

class LearningSwitch (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    self.listenTo(connection)
    self.arptable = {}
    self.mac = {}
    self.count = 0

  def handle_arp(self, event, packet):
    '''
    Handle the arp request if we can

    Note - this code was derived/inspired from the l3_learning.py switch in POX
    '''

    log.debug("we got an arp packet!!!" + str(event.connection.dpid))
   
    arp_req = packet.next
    if arp_req.prototype == arp.PROTO_TYPE_IP and arp_req.hwtype == arp.HW_TYPE_ETHERNET and arp_req.protosrc != 0:
        log.debug("arp proto source..." + str(arp_req.protosrc) + str(arp_req.protodst))
        
        # update the arp table
        self.arptable[arp_req.protosrc] = (event.port, packet.src, time.time() * ARP_TIMEOUT)

        # see if we can handle the arp request (we know the dst and it hasn't expired)
        if arp_req.opcode == arp.REQUEST and arp_req.protodst in self.arptable and self.arptable[arp_req.protodst][2] > time.time():
            # we can respond to the ARP request
            log.debug("responding to arp request...")

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
            arp_res.hwsrc = self.arptable[arp_req.protodst][1]

            # create an ethernet package that contains the arp response we created above
            e = ethernet(type=packet.type, src=dpid_to_mac(event.connection.dpid), dst=arp_req.hwsrc)
            e.set_payload(arp_res)
            log.debug("%i %i answering ARP for %s" % (event.connection.dpid, event.port, str(arp_res.protosrc)))

            # send the ARP response
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
            msg.in_port = event.port
            event.connection.send(msg)

            return

    # we don't know where this mac is, flood the packet
    log.debug("flooding arp packet!" + str(self.arptable))
    self.flood_packet(event)
    return 

  def flood_packet(self, event):
    '''
    Flood the given event to all links
    '''
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)

  def add_flow(self, event, source, destination, dst_port, data = None):
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

    #fm.buffer_id = event.ofp.buffer_id
    fm.actions.append(of.ofp_action_output(port = dst_port))
    log.debug("installing a new flow for %s to %s.%i " % (source, destination, dst_port) + str(self.count))
    self.connection.send(fm)

  def _handle_PacketIn (self, event):
    '''
    handles new packages that are sent to the controller
    '''
    # parsing the input packet
    packet = event.parse()

    # updating out mac to port mapping
    log.debug("received packet %s %s %s %s" % (str(packet.src), str(packet.dst), str(event.port), str(packet.next)))
    self.mac[packet.src] = event.port

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
    
    # update the ARP table
    self.arptable[packet.next.srcip] = (event.port, packet.src, time.time() + ARP_TIMEOUT)

    if packet.dst in self.mac:
        # we know the destination port, install a flow table rule
        self.count += 1 # keep track of the flow count - useful for debugging
        # TODO handle the case where the source and destination are the same...

        # create a new flow for this source and destination
        self.add_flow(event, packet.src, packet.dst, self.mac[packet.dst], event.ofp)

        # make a flow in the other direction
        self.add_flow(event, packet.dst, packet.src, event.port)

        return

    log.debug("Port for %s unknown -- flooding" % (packet.dst,))
    self.flood_packet(event)

class learning_switch (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection)

def launch ():
  #Starts an L2 learning switch.
  core.registerNew(learning_switch)
