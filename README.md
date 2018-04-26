# pcap_gen_ovs_dos
This python script can generate holePunching traffic trace...

Details are coming later...


usage: python pcap_generator_for_holepunch.py -t TYPE -o OUTPUT <other options>

Usage of PCAP generator for hole punching

optional arguments:
  -h, --help            show this help message and exit
  -t TYPE, --type TYPE  Specify the type: DP, SP_DP, DIP_SP_DP, SIP_DIP_SP_DP. 
                        DP will punch a hole only on the dst_port (udp) -> 17 packets!
                        SP_DP will punch holes on dst_port (UDP) and src_port (UDP) -> 17x17 packets
                        SIP_DP will punch holes on dst_port (UDP) and src_ip -> 17x33 packets
                        SIP_SP_DP will punch holes on dst_port (UDP), src_port (UDP) and dst_ip -> 17x17x33 packets
                        SIP_DIP_DP will punch holes on dst_port (UDP), dst_ip and src_ip -> 17x33x33
                        SIP_DIP_SP_DP will punch holes on dst_port (UDP), src_port (UDP), dst_ip and src_ip -> 17x17x33x33 packets
  -o OUTPUT, --output OUTPUT
                        Specify the output PCAP file's basename! Output will be [output].[PACKETSIZE]bytes.pcap extension is not needed!
  -a SRC_MAC, --src_mac SRC_MAC
                        Specify default source MAC address (for all packets), if not set default is 00:00:00:00:00:01
  -b DST_MAC, --dst_mac DST_MAC
                        Specify default source MAC address (for all packets), if not set default is 00:00:00:00:00:02
  -c SRC_IP, --src_ip SRC_IP
                        Specify src_ip for hole punching, if not set the default hole is 10.0.0.1
  -d DST_IP, --dst_ip DST_IP
                        Specify dst_ip for hole punching, if not set the default hole is 10.0.0.2
  -e SRC_PORT, --src_port SRC_PORT
                        Specify src_port for hole punching, if not set the default hole is 12345
  -f DST_PORT, --dst_port DST_PORT
                        Specify dst_port for hole punching, if not set the default hole is 80

