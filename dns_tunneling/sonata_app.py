#!/usr/bin/python

q1 = (PacketStream(1)
      # .filter(filter_keys=('ipv4.proto',), func=('eq', 17))
      .filter(filter_keys=('udp.sport',), func=('eq', 53))
      .filter(filter_keys=('dns.ancount',), func=('geq', 1))
      .map(keys=('dns.an.rdata',), map_values=('count',), func=('eq', 1,))
      .reduce(keys=('dns.an.rdata',), func=('sum',))

      )

q2 = (PacketStream(2)
      .filter(filter_keys=('tcp.dport',), func=('eq', 80))
      .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
      .reduce(keys=('ipv4.dstIP',), func=('sum',))
      )

T = 1
q3 = (q1.join(new_qid=3, query=q2)
      .map(keys=('dns.an.rdata', 'ipv4.dstIP',), map_values=('count1', 'count2',),
           func=('diff',))  # make output diff called 'diff3'
      .filter(filter_vals=('diff3',), func=('geq', T))
      .map(keys=('ipv4.dstIP'))
      )

config["final_plan"] = [(1, 32, 2, 1), (2, 8, 4, 1), (2, 32, 4, 1)]