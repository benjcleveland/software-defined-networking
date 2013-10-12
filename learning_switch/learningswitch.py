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

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30
class LearningSwitch (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    self.listenTo(connection)

    self.mac = {}
    self.count = 0

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()

    # updating out mac to port mapping
    log.debug("got packet %s %s %s" % (str(packet.src), str(packet.dst), str(event.port)))
    self.mac[packet.src] = event.port

    if packet.dst in self.mac:
        # install a flow table rule
        self.count += 1
        log.debug("installing a new flow table rule" + str(self.count))
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet)
        fm.idle_timeout = 30
        fm.hard_timeout = 60
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
