#!/usr/bin/python

T = 40

n_syn = (PacketStream(1)
         .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
         .filter(filter_keys=('tcp.flags',), func=('eq', 2))
         .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
         .reduce(keys=('ipv4.dstIP',), func=('sum',))
         .filter(filter_vals=('count',), func=('geq', T))
         .map(keys=('ipv4.dstIP',))
         )

config["final_plan"] = [(1, 8, 5, 1), (1, 32, 5, 1)]