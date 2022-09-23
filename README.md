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

List DNS Server responses
<pre><code>tshark -r <file.pcap> -Y "dns.qry.type == 1 and dns.a" -Tfields -e dns.qry.name -e dns.a</code></pre>

List the usernames and passwords used in FTP login attempts
<pre><code>tshark -r <file.pcap> -n -Y "ftp.request.command contains PASS || ftp.request.command contains USER"</code></pre>

List source IP, destination IP, destination port, tcp flags, sequence numbers and TCP length for all packets coming from 192.168.1.100 to destination port 80. Print the header for each field.
<pre><code>tshark -r <file.pcap> -E header=y -Y "ip.src==192.168.1.100 and tcp.dstport == 80" -Tfields -e ip.src -e ip.dst -e tcp.dstport -e tcp.flags -e tcp.seq -e tcp.len</code></pre>

Look for "NXDOMAIN" (rcode 3) returned in DNS responses (large number could mean kaminsky cache poisoning attempt).
<pre><code>tshark -r <file.pcap> -Y "dns.flags.response eq 1 and dns.flags.rcode eq 3" -Tfields -e dns.qry.name -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.flags.rcode -e dns.id</code></pre>

List all IP display filters.
<pre><code>tshark -G fields | awk -F " " '{for (i=1; i<=6; i++) print $i}' | grep "^ip\." | sort -u</code></pre>

 List all TCP display filters.
<pre><code>tshark -G fields | awk -F " " '{for (i=1; i<=6; i++) print $i}' | grep "^tcp\." | sort -u</code></pre>

Locate possible shellshock attempt.
<pre><code>tshark -r <file.pcap> -Y "http.request == 1" -Tfields -e http.user_agent | egrep "bin|bash"</code></pre>

In this example, the pcap contains DNS TXT records used for C2. The TXT records conatain a base64 encoded image file that we want to strip out of the PCAP. We will use Foremost to carve out the image.
<pre><code>tshark -r <file.pcap> -Y dns -Tfields -e dns.txt | while read txt; do echo $txt | base64 -d ; done > extracted</code></pre>
Now let's use Foremost to carve out the image. The exacted file contains the markers "FILE:" because the image is over multiple packets. We will strip this out and carve out the image with Foremost.
<pre><code>cat extracted | sed 's/FILE://g' | foremost -T -t jpeg -v -o /tmp/jpg</code></pre>

Print exact timestamp and packets for ESP from pcap file.
<pre><code>tshark -t ad -Y "ip.proto == 50" -r /nsm/pcapout/test.pcap</code></pre>

Print exact timestamp and packets for ISAKMP from pcap file.
<pre><code>tshark -t ad -Y "udp.port == 500" -r /nsm/pcapout/test.pcap</code></pre>

Print UDP packets for udp from pcap file. Only print ip src/dest, and udp port src/dest. Sort and print out count.
<pre><code>tshark -Y "ip.proto == 17" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -r /nsm/pcapout/test.pcap | sort | uniq -c | sort -nr</code></pre>

Print exact timestamp and UDP packets from pcap file. Only print timestamp, ip src/dest, and udp port src/dest.
<pre><code>tshark -t ad -Y "ip.proto == 17" -T fields -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -r /nsm/pcapout/test.pcap</code></pre>

## Tshark and SMB Examples

Create a display filter that matches all "Tree Connect  ANDX Response" messages: What shares we are trying to connect.
<pre><code>tshark -r <file.pcap> -Y "smb.cmd == 0x75 and smb.tid == 0"</code></pre>

Find all file requests from IP addresses except 10.3.58.4 and 10.3.58.9. Redirect output to a text file.
<pre><code>tshark -n -r <file.pcap> -Y '(smb.cmd == 0x0a2 && (smb.fid == 0)) && !(ip.addr == 10.3.58.4) && !(ip.addr == 10.3.58.9)' -Tfields -e ip.src -e ip.dst -e smb.path -e smb.file | sort | uniq -c | sort -nr > smb_files.txt</code></pre>

Create a display filter that matches all "Tree Connect  ANDX Response" messages: What shares we are trying to connect. Remove connection request for "\\CONTROLLER\\IPC$" and "\\CONTROLLER.SHIELDBASE.LOCAL\\IPC$" and "\\CONTROLLER.SHIELDBASE.LOCAL\\SYSVOL"
<pre><code>tshark -r <file.pcap> -Y '(smb.cmd == 0x75 and (smb.tid == 0)) and !(smb.path == "\\\\CONTROLLER\\IPC$") and !(smb.path == "\\\\CONTROLLER.SHIELDBASE.LOCAL\\IPC$") and !(smb.path == "\\\\CONTROLLER.SHIELDBASE.LOCAL\\SYSVOL")'</code></pre>

Look for SMB protocol negotiation
<pre><code>tshark -n -r <file.pcap> -Y "smb.cmd == 0x72"</code></pre>

Look for SMB session establishment where authentication negotiation is successful.
<pre><code>tshark -n -r <file.pcap> -Y "smb.cmd == 0x73 and spnego.negResult == 0x00"</code></pre>

Look for SMB service access or "Tree COnnect ANDX Request (UNC PATH" "Tree Connect ANDX Response (Tree ID)).
<pre><code>tshark -n -r <file.pcap> -Y "smb.cmd == 0x75"</code></pre>

Obtain SMB network directory metadata.
<pre><code>tshark -n -r <file.pcap> -Y "smb.cmd == 0x32 and smb.trans2.cmd == 0x0005 and smb.qpi_loi == 1004"</code></pre>

Look for SMB file open.
<pre><code>tshark -n -r <file.pcap> -Y "smb.cmd == 0xa2"</code></pre>

Filter all "NT Create ANDX Request" messages that contain a filename.
<pre><code>tshark -n -r <file.pcap> -Y "smb.cmd == 0xa2 and !(smb.fid) and smb.file"</code></pre>

Look for SMB2/SMB3 reading from a file.
<pre><code>tshark -E header=y -n -r <file.pcap> -Y "smb2.cmd == 0x05" -Tfields -e ip.src -e ip.dst -e smb2.filename | egrep -v "^$" | egrep -v "[0-9][[:space:]]$"</code></pre>

Look for SMB2 Tree Connect. Produce output with network shares.
<pre><code>tshark -E header=y -n -r <file.pcap> -Y "smb2.cmd == 0x03"</code></pre>

