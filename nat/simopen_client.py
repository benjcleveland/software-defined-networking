#!/usr/bin/env python

import socket
import time

s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.bind(('10.0.1.101', 2222))
print 'bound!'
time.sleep(5)
print 'connecting...'
s1.connect(('172.64.3.21', 1112))
    
s1.send('world')
print s1.recv(5)
s1.shutdown(socket.SHUT_RDWR)
s1.close()
