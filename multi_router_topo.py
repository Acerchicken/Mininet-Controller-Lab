#!/usr/bin/python
# -*- coding: utf-8 -*-

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class MyTopo(Topo):
    def build(self):
        # ===== Switches =====
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # ===== Hosts & Links (Cố định Port cho Host là 1, 2) =====
        
        # Subnet A (s1): Port 1, 2 cho Host
        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        self.addLink(h1, s1, port2=1) # h1 -> s1-eth1
        self.addLink(h2, s1, port2=2) # h2 -> s1-eth2

        # Subnet B (s2): Port 1, 2 cho Host
        h3 = self.addHost('h3', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        h4 = self.addHost('h4', ip='10.0.2.3/24', defaultRoute='via 10.0.2.1')
        self.addLink(h3, s2, port2=1) # h3 -> s2-eth1
        self.addLink(h4, s2, port2=2) # h4 -> s2-eth2

        # Subnet C (s3): Port 1, 2 cho Host
        h5 = self.addHost('h5', ip='10.0.3.2/24', defaultRoute='via 10.0.3.1')
        h6 = self.addHost('h6', ip='10.0.3.3/24', defaultRoute='via 10.0.3.1')
        self.addLink(h5, s3, port2=1) # h5 -> s3-eth1
        self.addLink(h6, s3, port2=2) # h6 -> s3-eth2

        # ===== Inter-Switch Links (Cố định Port liên kết là 3, 4) =====
        info( '*** Creating links between switches with fixed ports\n' )
        
        # s1(3) <---> s2(3)
        self.addLink(s1, s2, port1=3, port2=3)
        
        # s2(4) <---> s3(3)
        self.addLink(s2, s3, port1=4, port2=3)
        
        # s3(4) <---> s1(4)
        #self.addLink(s3, s1, port1=4, port2=4)

# Register topology with Mininet
topos = { 'mytopo': ( lambda: MyTopo() ) }