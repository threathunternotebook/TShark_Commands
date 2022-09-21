# TShark_Commands

Print available tshark fields for IP, TCP, and UDP.
<pre><code>tshark -G fields | awk -F "\t" '{print $3}' | grep -P "^tcp\.|^ip\.|^udp\." | sort -u</code></pre>

List all known protocols in a PCAP file
<pre><code>tshark -r <file.pcap> -qz io,phs</code></pre>

List IP addresses.
<pre><code>tshark -r <file.pcap> -qz ip_hosts,tree</code></pre>

List all web pages requested by hosts.
<pre><code>tshark -r <file.pcap> -qz http_req,tree</code></pre>

List Ethernet hosts (source only).
<pre><code>tshark -r <file.pcap> -Tfields -e "eth.src" | sort -u</code></pre>

List Ethernet hosts (destination only).
<pre><code>tshark -r <file.pcap> -Tfields -e "eth.dst" | sort -u</code></pre>

List Netbios hostnames using NBNS and Windows BROWSER protocols.
<pre><code>tshark -r <file.pcap> -Y "browser.command==1" -Tfields -e "ip.src" -e "browser.server" | uniq</code></pre>

List web browser used in PCAP file.
<pre><code>tshark -r <file.pcap> -Y "http.request" -Tfields -e "ip.src" -e "http.user_agent" | uniq</code></pre>

Send output to JSON file. This may not be available in some versions. Check for updated Tshark. Available in 3.6.2.
<pre><code>tshark -T ek -x -r file.pcap > output.json</code></pre>

List domain names involved in communications where the first column is the requesting host or DNS Server IP address, the second column indicates if this is a query(0) or a response (1) and the third column displays the query.
<pre><code>tshark -r <file.pcap> -Y "dns" -Tfields -e "ip.src" -e "dns.flags.response" -e "dns.qry.name"</code></pre>

Locate SSL heartbleed packets
<pre><code>tshark -r <file.pcap> -O ssl "ssl.heartbeat_message.payload_length > 100"</code></pre>
<pre><code>tshark -r <file.pcap> -Y "tcp.port==443" -Tfields -e ip.src -e ip.dst -e ip.len -e ssl.heartbeat_message.payload_length</code></pre>


<pre><code></code></pre>

<pre><code> </code></pre>
Print exact timestamp and packets for ESP from pcap file.
<pre><code>tshark -t ad -Y "ip.proto == 50" -r /nsm/pcapout/test.pcap</code></pre>

Print exact timestamp and packets for ISAKMP from pcap file.
<pre><code>tshark -t ad -Y "udp.port == 500" -r /nsm/pcapout/test.pcap</code></pre>

Print UDP packets for udp from pcap file. Only print ip src/dest, and udp port src/dest. Sort and print out count.
<pre><code>tshark -Y "ip.proto == 17" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -r /nsm/pcapout/test.pcap | sort | uniq -c | sort -nr</code></pre>

Print exact timestamp and UDP packets from pcap file. Only print timestamp, ip src/dest, and udp port src/dest.
<pre><code>tshark -t ad -Y "ip.proto == 17" -T fields -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -r /nsm/pcapout/test.pcap</code></pre>
