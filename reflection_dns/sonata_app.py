#!/usr/bin/python

reflection_dns = (PacketStream(1)
                .filter(filter_keys=('ipv4.protocol',), func=('eq', 17))
                .filter(filter_keys=('udp.sport',), func=('eq', 53))
                .filter(filter_keys=('dns.ns.type',), func=('eq', 46))
                .map(keys=('ipv4.dstIP', 'ipv4.srcIP'))
                .distinct(keys=('ipv4.dstIP', 'ipv4.srcIP'))
                .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
                .reduce(keys=('ipv4.dstIP',), func=('sum',))
                .filter(filter_vals=('count',), func=('geq', 40))
                .map(keys=('ipv4.dstIP',))
                )

config["final_plan"] = [(1, 8, 3, 1), (1, 32, 3, 1)]
