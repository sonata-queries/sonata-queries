#!/usr/bin/python

ddos = (PacketStream(1)
        .map(keys=('ipv4.dstIP', 'ipv4.srcIP'))
        .distinct(keys=('ipv4.dstIP', 'ipv4.srcIP'))
        .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
        .reduce(keys=('ipv4.dstIP',), func=('sum',))
        .filter(filter_vals=('count',), func=('geq', 45))
        .map(keys=('ipv4.dstIP',))
        )

config["final_plan"] = [(1, 8, 5, 1), (1, 32, 5, 1)]
