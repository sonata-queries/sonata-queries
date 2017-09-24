#!/usr/bin/python


brute_ssh = (PacketStream(1)
             .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
             .filter(filter_keys=('tcp.dport',), func=('eq', 23))
             .map(keys=('ipv4.dstIP', 'ipv4.srcIP', 'ipv4.totalLen'))
             .distinct(keys=('ipv4.dstIP', 'ipv4.srcIP', 'ipv4.totalLen'))
             .map(keys=('ipv4.dstIP', 'ipv4.totalLen'))
             .map(keys=('ipv4.dstIP', 'ipv4.totalLen'), map_values=('count',), func=('eq', 1,))
             .reduce(keys=('ipv4.dstIP', 'ipv4.totalLen'), func=('sum',))
             .filter(filter_vals=('count',), func=('geq', 40))
             .map(keys=('ipv4.dstIP',))
             )

dorros_payload = (PacketStream(2)
                  .map(keys=('ipv4.dstIP', 'payload'))
                  )

dorros_attack = (dorros_payload.join(new_qid=3, query=brute_ssh)
                 .filter(filter_keys=('ipv4.protocol',), func=('eq', 6))
                 .filter(filter_keys=('tcp.dport',), func=('eq', 23))
                 .filter(filter_vals=('payload',), func=('eq', 'zorro'))
                 .map(keys=('ipv4.dstIP', 'payload',), map_values=('count',), func=('eq', 1))
                 .reduce(keys=('ipv4.dstIP', 'payload',), func=('sum',))
                 .map(keys=('ipv4.dstIP',))
                 )


config["final_plan"] = [(1, 8, 8, 1), (1, 32, 8, 1), (3, 32, 4, 1)]
