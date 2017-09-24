#!/usr/bin/python

q1 = (PacketStream(1)
      .map(keys=('ipv4.dstIP', 'ipv4.srcIP'))
      .distinct(keys=('ipv4.dstIP', 'ipv4.srcIP'))
      .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
      .reduce(keys=('ipv4.dstIP',), func=('sum',))
      .filter(filter_vals=('count',), func=('geq', 45))
      .map(keys=('ipv4.dstIP',))
      )

q2 = (PacketStream(2)
      .map(keys=('ipv4.dstIP', 'payload'))
      )

q3 = (q2.join(new_qid=3, query=q1)
      .map(keys=('ipv4.dstIP', 'payload'), map_values=('count',), func=('eq', 1))
      .reduce(keys=('ipv4.dstIP', 'payload'), func=('sum',))
      .filter(filter_vals=('count',), func=('geq', 1))
      .map(keys=('ipv4.dstIP',))
      .distinct(keys=('ipv4.dstIP',))
      )

config["final_plan"] = [(1, 8, 5, 1), (1, 32, 5, 1), (3, 8, 1, 1), (3, 32, 1, 1)]