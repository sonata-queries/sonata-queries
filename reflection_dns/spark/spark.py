pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('10008'))).map(lambda p: (p[2:])).map(
    lambda ((udp_sport, ipv4_srcIP, ipv4_protocol, ipv4_dstIP, dns_ns_type)): (
    (udp_sport, ipv4_srcIP, ipv4_protocol, ipv4_dstIP, dns_ns_type))).filter(
    lambda ((udp_sport, ipv4_srcIP, ipv4_protocol, ipv4_dstIP, dns_ns_type)): ((float(dns_ns_type) == 46))).map(
    lambda ((udp_sport, ipv4_srcIP, ipv4_protocol, ipv4_dstIP, dns_ns_type)): (
    (ipv4_dstIP, ipv4_srcIP))).distinct().map(lambda ((ipv4_dstIP, ipv4_srcIP)): ((ipv4_dstIP), (1))).reduceByKey(
    lambda x, y: x + y).filter(lambda ((ipv4_dstIP), (count)): ((float(count) >= 40))).map(
    lambda ((ipv4_dstIP), (count)): ((ipv4_dstIP))))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '10008'))
pktstream.window(self.window_length, self.sliding_interval).transform(lambda rdd: (
rdd.filter(lambda p: (p[1] == str('10032'))).map(lambda p: (p[2:])).map(
    lambda ((udp_sport, ipv4_srcIP, ipv4_protocol, ipv4_dstIP, dns_ns_type)): (
    (udp_sport, ipv4_srcIP, ipv4_protocol, ipv4_dstIP, dns_ns_type))).filter(
    lambda ((udp_sport, ipv4_srcIP, ipv4_protocol, ipv4_dstIP, dns_ns_type)): ((float(dns_ns_type) == 46))).map(
    lambda ((udp_sport, ipv4_srcIP, ipv4_protocol, ipv4_dstIP, dns_ns_type)): (
    (ipv4_dstIP, ipv4_srcIP))).distinct().map(lambda ((ipv4_dstIP, ipv4_srcIP)): ((ipv4_dstIP), (1))).reduceByKey(
    lambda x, y: x + y).filter(lambda ((ipv4_dstIP), (count)): ((float(count) >= 40))).map(
    lambda ((ipv4_dstIP), (count)): ((ipv4_dstIP))))).foreachRDD(
    lambda rdd: send_reduction_keys(rdd, (u'localhost', 4949), 0, '10032'))
