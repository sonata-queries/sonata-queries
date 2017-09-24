#!/usr/bin/python


n_syn = (PacketStream(1)
         .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
         .filter(filter_keys=('tcp.flags',), func=('eq', 2))
         .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
         .reduce(keys=('ipv4.dstIP',), func=('sum',))
         )

n_fin = (PacketStream(2)
         .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
         .filter(filter_keys=('tcp.flags',), func=('eq', 1))
         .map(keys=('ipv4.srcIP',), map_values=('count',), func=('eq', 1,))
         .reduce(keys=('ipv4.srcIP',), func=('sum',))
         )

T = 1
diff_query = (n_syn.join(new_qid=3, query=n_fin)
      .map(keys=('ipv4.dstIP', 'ipv4.srcIP',), map_values=('count1', 'count2',), func=('diff',))
      .filter(filter_vals=('diff3',), func=('geq', T))
      .map(keys=('ipv4.dstIP'))
      )

config["final_plan"] = [(1, 8, 2, 1), (1, 32, 2, 1), (2, 8, 2, 1), (2, 32, 2, 1)]