#!/usr/bin/python
T = 1

# super spreader detection
# One host makes too many connections to different

super_spreader = (PacketStream(1)
                  .map(keys=('ipv4.dstIP', 'ipv4.srcIP'))
                  .distinct(keys=('ipv4.dstIP', 'ipv4.srcIP'))
                  .map(keys=('ipv4.srcIP',), map_values=('count',), func=('eq', 1,))
                  .reduce(keys=('ipv4.srcIP',), func=('sum',))
                  .filter(filter_vals=('count',), func=('geq', 40))
                  .map(keys=('ipv4.srcIP',))
                  )

config["final_plan"] = [(1, 32, 3, 1)]
