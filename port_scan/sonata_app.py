#!/usr/bin/python
T = 40

# port scan
# One host is scanning lot of different ports
# this potentially happens before an attack
port_scan = (PacketStream(1)
             .map(keys=('ipv4.srcIP', 'tcp.dport'))
             .distinct(keys=('ipv4.srcIP', 'tcp.dport'))
             .map(keys=('ipv4.srcIP',), map_values=('count',), func=('eq', 1,))
             .reduce(keys=('ipv4.srcIP',), func=('sum',))
             .filter(filter_vals=('count',), func=('geq', T))
             .map(keys=('ipv4.srcIP',))
             )

config["final_plan"] = [(1, 8, 5, 1), (1, 32, 5, 1)]
