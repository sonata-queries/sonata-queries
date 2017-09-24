# sonata-queries


| Program Name  | Description|
| ------------- | ------------- |
| TCP New Conn | for which the number of newly opened TCP connections exceeds threshold.|
| SSH Brute     | that receive similar-sized packets from more than threshold unique senders.|
| SuperSpreader | that contact more than threshold unique destinations.|
| Port Scan     | that send traffic over more than threshold destination ports.|
| DDoS          |that receive traffic from more than threshold unique sources.|
| Syn Flood     | for which the number of half-open TCP connections exceeds threshold Th. |
| Completed Flow| for which the number of incomplete TCP connections exceeds threshold.|
| Slowloris Attack | for which the average transfer rate per flow is below threshold.|
| DNS Tunneling | for which new TCP connections are not created after DNS query.|
| Zorro Attck | that receive “zorro” command after telnet brute force.|
| Reflection DNS| that receive DNS response of type “RRSIG” from many unique senders without requests.|
