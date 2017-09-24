#!/usr/bin/python

T1 = 10
T2 = 10
n_conns = (PacketStream(1)
           .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
           .map(keys=('ipv4.dstIP', 'ipv4.srcIP', 'tcp.sport',))
           .distinct(keys=('ipv4.dstIP', 'ipv4.srcIP', 'tcp.sport',))
           .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
           .reduce(keys=('ipv4.dstIP',), func=('sum',))
           .filter(filter_vals=('count',), func=('geq', T1))
           )

n_bytes = (PacketStream(2)
           .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
           .map(keys=('ipv4.dstIP', 'ipv4.totalLen',))
           .map(keys=('ipv4.dstIP',), map_values=('ipv4.totalLen',))
           .reduce(keys=('ipv4.dstIP',), func=('sum',))
           )

slowloris = (n_bytes.join(window='Same', new_qid=3, query=n_conns)
             .map(map_values=('count2',), func=('div',))
             .filter(filter_keys=('count2',), func=('geq', T2))
             )

config["final_plan"] = [(1, 8, 6, 1), (1, 32, 6, 1), (2, 8, 5, 1), (2, 32, 5, 1)]
