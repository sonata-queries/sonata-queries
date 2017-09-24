pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('10008'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_dstIP, count)): ((ipv4_dstIP), (count))).reduceByKey(lambda x, y: x + y).filter(
    lambda ((ipv4_dstIP), (count)): ((float(count) >= 45))).map(
    lambda ((ipv4_dstIP), (count)): ((ipv4_dstIP))))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '10008'))
pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('10032'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_dstIP, count)): ((ipv4_dstIP), (count))).reduceByKey(lambda x, y: x + y).filter(
    lambda ((ipv4_dstIP), (count)): ((float(count) >= 45))).map(
    lambda ((ipv4_dstIP), (count)): ((ipv4_dstIP))))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '10032'))
pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('30032'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_dstIP, payload)): ((ipv4_dstIP, payload))).map(
    lambda ((ipv4_dstIP, payload)): ((ipv4_dstIP, payload), (1))).reduceByKey(lambda x, y: x + y).filter(
    lambda ((ipv4_dstIP, payload), (count)): ((float(count) >= 1))).map(
    lambda ((ipv4_dstIP, payload), (count)): ((ipv4_dstIP))).distinct())).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '30032'))
pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('30008'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_dstIP, payload)): ((ipv4_dstIP, payload))).map(
    lambda ((ipv4_dstIP, payload)): ((ipv4_dstIP, payload), (1))).reduceByKey(lambda x, y: x + y).filter(
    lambda ((ipv4_dstIP, payload), (count)): ((float(count) >= 1))).map(
    lambda ((ipv4_dstIP, payload), (count)): ((ipv4_dstIP))).distinct())).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '30008'))
