#!/usr/bin/env python

from pox.core import core
from pox.lib.revent import *

from learning_switch import learningswitch

log = core.getLogger()

class nat(EventMixin):
    def __init__(self, connection):
        # add the nat to this switch
        self.connection = connection
        self.listenTo(connection)
        
        #todo...

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
