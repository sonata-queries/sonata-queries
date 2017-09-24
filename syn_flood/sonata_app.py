#!/usr/bin/python

n_syn = (PacketStream(1)
         .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
         .filter(filter_keys=('tcp.flags',), func=('eq', 2))
         .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
         .reduce(keys=('ipv4.dstIP',), func=('sum',))
         )

n_synack = (PacketStream(2)
            .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
            .filter(filter_keys=('tcp.flags',), func=('eq', 17))
            .map(keys=('ipv4.srcIP',), map_values=('count',), func=('eq', 1,))
            .reduce(keys=('ipv4.srcIP',), func=('sum',))
            )

n_ack = (PacketStream(3)
         .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
         .filter(filter_keys=('tcp.flags',), func=('eq', 16))
         .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
         .reduce(keys=('ipv4.dstIP',), func=('sum',))
         )

Th = 3
syn_flood_victim = (n_syn
                    .join(window='Same',new_qid=4, query=n_synack)
                    .map(map_keys=('ipv4.dstIP'), map_values=('count1', 'count2'), func=('sum'))
                    .join(window='Same',new_qid=5, query=n_ack)
                    .map(keys=('ipv4.dstIP'), map_values=('count12', 'count3'), func=('diff', 1,))
                    .filter(filter_keys=('count'), func=('geq', Th))
                    )


config["final_plan"] = [(1, 16, 4, 1), (1, 32, 4, 1),
                        (2, 16, 4, 1), (2, 32, 4, 1),
                        (3, 16, 4, 1), (3, 32, 4, 1),
                        ]