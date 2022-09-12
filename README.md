# TShark_Commands

Print available tshark fields for IP, TCP, and UDP.
<pre><code>tshark -G fields | awk -F "\t" '{print $3}' | grep -P "^tcp\.|^ip\.|^udp\." | sort -u</code></pre>

Print exact timestamp and packets for ESP from pcap file.
<pre><code>tshark -t ad -Y "ip.proto == 50" -r /nsm/pcapout/test.pcap</code></pre>

Print exact timestamp and packets for ISAKMP from pcap file.
<pre><code>tshark -t ad -Y "udp.port == 500" -r /nsm/pcapout/test.pcap</code></pre>

Print UDP packets for udp from pcap file. Only print ip src/dest, and udp port src/dest. Sort and print out count.
<pre><code>tshark -Y "ip.proto == 17" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -r /nsm/pcapout/test.pcap | sort | uniq -c | sort -nr</code></pre>

Print exact timestamp and UDP packets from pcap file. Only print timestamp, ip src/dest, and udp port src/dest.
<pre><code>tshark -t ad -Y "ip.proto == 17" -T fields -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -r /nsm/pcapout/test.pcap</code></pre>
