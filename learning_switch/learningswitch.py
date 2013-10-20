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

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30

# todo - is there a better way to do this? get the mac address
def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

class LearningSwitch (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    self.listenTo(connection)
    self.arptable = {}
    self.mac = {}
    self.count = 0

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()

    # updating out mac to port mapping
    log.debug("got packet %s %s %s %s" % (str(packet.src), str(packet.dst), str(event.port), str(packet.next)))
    self.mac[packet.src] = event.port

    # handle arp?
    if isinstance(packet.next, arp):
        log.debug("we got an arp packet!!!" + str(event.connection.dpid))

        arp_req = packet.next
        if arp_req.prototype == arp.PROTO_TYPE_IP and arp_req.hwtype == arp.HW_TYPE_ETHERNET and arp_req.protosrc != 0:
            # todo, do something here...
            log.debug("arp proto source..." + str(arp_req.protosrc) + str(arp_req.protodst))
            # update the arp table
            # TODO - the entries in the arp table should time out after some amount of time...
            self.arptable[arp_req.protosrc] = (event.port, packet.src)

            if arp_req.opcode == arp.REQUEST and arp_req.protodst in self.arptable:
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
                e = ethernet(type=packet.type, src=dpid_to_mac(event.connection.dpid), dst=arp_req.hwsrc)
                e.set_payload(arp_res)
                log.debug("%i %i answering ARP for %s" % (event.connection.dpid, event.port,
                 str(arp_res.protosrc)))
                msg = of.ofp_packet_out()
                msg.data = e.pack()
                msg.actions.append(of.ofp_action_output(port =
                                                        of.OFPP_IN_PORT))
                msg.in_port = event.port
                event.connection.send(msg)
                return

        log.debug("flooding arp packet!" + str(self.arptable))
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)
        return

    if packet.dst in self.mac:
        # install a flow table rule
        self.count += 1
        log.debug("installing a new flow table rule for %s.%i to %s.%i " % (packet.src, event.port, packet.dst, self.mac[packet.dst]) + str(self.count))
        # todo handle the case where the source and destination are the same...
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet)
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.buffer_id = event.ofp.buffer_id
        fm.actions.append(of.ofp_action_output(port = self.mac[packet.dst]))
    
        # forward the packet to the destination
        self.connection.send(fm)
        return

    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      return

    log.debug("Port for %s unknown -- flooding" % (packet.dst,))
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)

class learning_switch (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection)

def launch ():
  #Starts an L2 learning switch.
  core.registerNew(learning_switch)
