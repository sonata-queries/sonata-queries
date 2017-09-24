#!/usr/bin/python


brute_ssh = (PacketStream(1)
             .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
             .filter(filter_keys=('tcp.dport',), func=('eq', 22))
             .map(keys=('ipv4.dstIP', 'ipv4.srcIP', 'ipv4.totalLen'))
             .distinct(keys=('ipv4.dstIP', 'ipv4.srcIP', 'ipv4.totalLen'))
             .map(keys=('ipv4.dstIP', 'ipv4.totalLen'))
             .map(keys=('ipv4.dstIP', 'ipv4.totalLen'), map_values=('count',), func=('eq', 1,))
             .reduce(keys=('ipv4.dstIP', 'ipv4.totalLen'), func=('sum',))
             .filter(filter_vals=('count',), func=('geq', 40))
             .map(keys=('ipv4.dstIP',))
             )

config["final_plan"] = [(1, 8, 3, 1), (1, 32, 3, 1)]
