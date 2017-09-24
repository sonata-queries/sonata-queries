pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('10016'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_dstIP)): ((ipv4_dstIP), (count))).reduceByKey(lambda x, y: x + y))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '10016'))

pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('20032'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_srcIP)): ((ipv4_srcIP), (count))).reduceByKey(lambda x, y: x + y))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '20032'))

pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('30016'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_dstIP)): ((ipv4_dstIP), (count))).reduceByKey(lambda x, y: x + y))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '30016'))

pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('30032'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_dstIP)): ((ipv4_dstIP), (count))).reduceByKey(lambda x, y: x + y)))

pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('10032'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_dstIP)): ((ipv4_dstIP), (count))).reduceByKey(lambda x, y: x + y))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '10032'))

pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('20016'))).map(lambda p: (p[2:])).map(
    lambda ((ipv4_srcIP)): ((ipv4_srcIP), (count))).reduceByKey(lambda x, y: x + y))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '20016'))

spark_queries[10032].join(spark_queries[20032])
    .map(lambda (IP, (count1, count2)): (IP, (count1 + count2)))
    .join(spark_queries[30032])
    .map(lambda (IP, (count12, count3)): (IP, (count12 - count3)))
    .filter(lambda (IP, count): count > 3)
    .foreachRDD(lambda rdd: print("Join " + str(rdd.take(5))))