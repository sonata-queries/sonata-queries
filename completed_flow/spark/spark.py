pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('10008'))).map(lambda p: (p[2:])).map(
    lambda ((tcp_flags, ipv4_protocol, ipv4_dstIP)): ((tcp_flags, ipv4_protocol, ipv4_dstIP))).filter(
    lambda ((tcp_flags, ipv4_protocol, ipv4_dstIP)): ((float(tcp_flags) == 2))).map(
    lambda ((tcp_flags, ipv4_protocol, ipv4_dstIP)): ((ipv4_dstIP), (1))).reduceByKey(lambda x, y: x + y))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '10008'))
pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('10032'))).map(lambda p: (p[2:])).map(
    lambda ((tcp_flags, ipv4_protocol, ipv4_dstIP)): ((tcp_flags, ipv4_protocol, ipv4_dstIP))).filter(
    lambda ((tcp_flags, ipv4_protocol, ipv4_dstIP)): ((float(tcp_flags) == 2))).map(
    lambda ((tcp_flags, ipv4_protocol, ipv4_dstIP)): ((ipv4_dstIP), (1))).reduceByKey(lambda x, y: x + y))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '10032'))
pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('20032'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_protocol, ipv4_srcIP, tcp_flags)): ((ipv4_protocol, ipv4_srcIP, tcp_flags))).filter(
    lambda ((ipv4_protocol, ipv4_srcIP, tcp_flags)): ((float(tcp_flags) == 1))).map(
    lambda ((ipv4_protocol, ipv4_srcIP, tcp_flags)): ((ipv4_srcIP), (1))).reduceByKey(lambda x, y: x + y))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '20032'))
pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('20008'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_protocol, ipv4_srcIP, tcp_flags)): ((ipv4_protocol, ipv4_srcIP, tcp_flags))).filter(
    lambda ((ipv4_protocol, ipv4_srcIP, tcp_flags)): ((float(tcp_flags) == 1))).map(
    lambda ((ipv4_protocol, ipv4_srcIP, tcp_flags)): ((ipv4_srcIP), (1))).reduceByKey(lambda x, y: x + y))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '20008'))
