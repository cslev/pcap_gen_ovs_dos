#!/usr/bin/python

import sys
import binascii
import random
import copy
import argparse
import textwrap

#Global header for pcap 2.4
pcap_global_header =   ('D4 C3 B2 A1'
                        '02 00'         #File format major revision (i.e. pcap <2>.4)
                        '04 00'         #File format minor revision (i.e. pcap 2.<4>)
                        '00 00 00 00'
                        '00 00 00 00'
                        'FF FF 00 00'
                        '01 00 00 00')

#pcap packet header that must preface every packet
pcap_packet_header =   ('AA 77 9F 47'
                        '90 A2 04 00'
                        'XX XX XX XX'   #Frame Size (little endian)
                        'YY YY YY YY')  #Frame Size (little endian)

eth_header =   ('00 E0 4C 00 00 01'     #Dest Mac
                '00 04 0B 00 00 02'     #Src Mac
                '08 00')                #Protocol (0x0800 = IP)

ip_header =    ('45'                    #IP version and header length (multiples of 4 bytes)
                '00'
                'XX XX'                 #Length - will be calculated and replaced later
                '00 00'
                '40 00 TT'              ## TT is TTL
                '11'                    #Protocol (0x11 = UDP)
                'YY YY'                 #Checksum - will be calculated and replaced later
                '0A 00 00 01'           #Source IP (Default: 10.0.0.1)
                '0A 00 00 02')          #Dest IP (Default: 10.0.0.2)

udp_header =   ('ZZ ZZ'                 # TODO
                'XX XX'                 #Port - will be replaced later
                'YY YY'                 #Length - will be calculated and replaced later
                '00 00')

packet_sizes = (64,) #,                     #PCAP file will be generated for these
                # 128,                    #packet sizes
                # 256,
                # 512,
                # 1024,
                # 1280,
                # 1500)

BASE_TTL=40



def getByteLength(str1):
    return len(''.join(str1.split())) / 2

def writeByteStringToFile(bytestring, filename):
    bytelist = bytestring.split()
    bytes = binascii.a2b_hex(''.join(bytelist))
    bitout = open(filename, 'ab')
    bitout.write(bytes)

def backspace(n):
    # print((b'\x08' * n).decode(), end='') # use \x08 char to go back
    sys.stdout.write('\r' * n)                 # use '\r' to go back

def calculateRemainingPercentage(current,n):
#     print("%d - %d" % (current,n))
    percent = str("all-byte packets: %d%%" % (int((current/float(n)) * 100)))
    sys.stdout.write(percent)

    backspace(len(percent))                       # back for n chars
#     return ((current/n) * 100)

def negate_bit(bit):
    if bit == "1":
        return "0"
    return "1"

def generateHolePunchDP(pcapfile, dp, ttl):
    global BASE_TTL
    # write out header information to file
    nfo_file = str("%s.nfo" % pcapfile)
    writeoutLine(nfo_file, str("#src_mac,#dst_mac,#vlan,#src_ip,#dst_ip,#src_port,#dst_port"))

    sport = default_sp
    src_ip = parseIP(default_sip)   #10.0.0.1
    dst_ip = parseIP(default_dip)   #10.0.0.2
    # print dst_ip
    src_mac = parseMAC(default_smac)
    dst_mac = parseMAC(default_dmac)

    # get the binary representation
    dport = '{0:016b}'.format(int(dp))
    # int(dport,2) will convert it back to decimal

    # generate all other ports from dport by negating bits from left to right
    other_ports = list()


    dport_len = len(dport)  # obviously it is always 16 :)

    n = dport_len+1
    print "dport_len: {}".format(n)
    if n > 17:
        print "Too many packets! Destination port number is only 16 bits wide!"
        return


    for bit in range(0,dport_len):
        tmp_port = copy.deepcopy(dport)
        tmp_port = list(tmp_port)
        tmp_port[bit]=negate_bit(tmp_port[bit])
        new_port = ''.join(tmp_port)
        other_ports.append(copy.deepcopy(int(new_port,2)))
    # append the set DP as well to the list
    other_ports.append(int(dp))

    print "The following ports could punch a hole in megaflow cache"
    print other_ports

    created_packets=0
    num_packets = int(ttl) * n
    print "Number of packets to be generated: {}".format(num_packets)
    # #ttl trick
    for t in range(0, int(ttl)):
        BASE_TTL = BASE_TTL + 1

        for i in range(0, n):
            created_packets+=1
            # print created_packets

            calculateRemainingPercentage(created_packets, num_packets)


            #first we put one package into the file whose destination port number is $dp
            # update ethernet header
            eth_header = dst_mac + ' ' + src_mac + "0800"
            # update ip header
            ip_header = ('45'
                         '00'
                         'XX XX'
                         '00 00'
                         '40 00 TT'
                         '11'
                         'YY YY')
            ip_header = ip_header.replace('TT', "%02x" % BASE_TTL)
            # print ip_header

            ip_header += src_ip
            ip_header += dst_ip

            udp = udp_header.replace('XX XX', "%04x" % other_ports[i])

            udp = udp.replace('ZZ ZZ', "%04x" % sport)


            for pktSize in packet_sizes:
                message = getMessage(pktSize)

                udp_len = getByteLength(message) + getByteLength(udp_header)
                udp = udp.replace('YY YY', "%04x" % udp_len)

                ip_len = udp_len + getByteLength(ip_header)
                ip = ip_header.replace('XX XX', "%04x" % ip_len)
                checksum = ip_checksum(ip.replace('YY YY', '00 00'))
                ip = ip.replace('YY YY', "%04x" % checksum)

                pcap_len = ip_len + getByteLength(eth_header)
                hex_str = "%08x" % pcap_len
                reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
                pcaph = pcap_packet_header.replace('XX XX XX XX', reverse_hex_str)
                pcaph = pcaph.replace('YY YY YY YY', reverse_hex_str)

                if i == 0 and t == 0:
                    bytestring = pcap_global_header + pcaph + eth_header + ip + udp + message

                else:
                    bytestring = pcaph + eth_header + ip + udp + message

                writeByteStringToFile(bytestring, pcapfile + str(".%dbytes.pcap" % pktSize))

                # write out random values to file
            # convert hex src MAC to string
            src_mac_str = ""
            for i, j in enumerate(src_mac):
                if (i != 0) and (i % 2) == 0:
                    src_mac_str += ":"
                src_mac_str += j
                # convert hex dst MAC to string
            dst_mac_str = ""
            for i, j in enumerate(dst_mac):
                if (i != 0) and (i % 2) == 0:
                    dst_mac_str += ":"
                dst_mac_str += j

                # convert hex dst IP to string
            dst_ip_str = ""
            start = 0
            stop = 2
            for i, j in enumerate(dst_ip):
                b = i + 1
                if b % 2 == 0:
                    dst_ip_str += str(int(dst_ip[start:stop], 16))
                    start += 2
                    stop += 2
                    if (b != len(dst_ip)):
                        dst_ip_str += "."

            # convert hex src IP to string
            src_ip_str = ""
            start = 0
            stop = 2
            for i, j in enumerate(src_ip):
                b = i + 1
                if b % 2 == 0:
                    src_ip_str += str(int(src_ip[start:stop], 16))
                    start += 2
                    stop += 2
                    if (b != len(src_ip)):
                        src_ip_str += "."

                        # convert ports to sting
            src_port_str = str(sport)
            dst_port_str = str(dport)

            ##src_mac,#dst_mac,#src_ip,#dst_ip,#src_port,#dst_port
            line = src_mac_str + "," + dst_mac_str + "," + \
                   src_ip_str + "," + dst_ip_str + "," + \
                   src_port_str + "," + dst_port_str
            writeoutLine(nfo_file, line)


def generateHolePunchSIPDP(pcapfile, sip, dp, ttl):
    '''
    :param pcapfile: filename
    :param sip: source ip
    :param dp: destination port
    :return:
    '''
    global BASE_TTL

    src_ip = parseIP(sip)
    src_ip_bin = '{0:032b}'.format(int(src_ip, 16))  # convert hex to int and then to bin string

    dst_ip = parseIP(default_dip)
    # print dst_ip
    src_mac = parseMAC(default_smac)
    dst_mac = parseMAC(default_dmac)

    # get the binary representation
    sport = default_sp
    dport = '{0:016b}'.format(int(dp))
    # int(dport,2) will convert it back to decimal

    # generate all other ports from dport by negating bits from left to right
    other_dst_ports = list()

    dport_len = len(dport)
    for bit in range(0, dport_len):  # port is 16 bit wide
        tmp_port = copy.deepcopy(dport)
        tmp_port = list(tmp_port)
        tmp_port[bit] = negate_bit(tmp_port[bit])
        new_port = ''.join(tmp_port)
        other_dst_ports.append(copy.deepcopy(int(new_port, 2)))
    # append the set DP to the list
    other_dst_ports.append(int(dp))


    # generate all IPs with only 1 bit difference
    other_src_ips = list()
    other_src_ips.append(src_ip)
    sip_len = 32
    print "sip_len: {}".format(sip_len)
    for bit in range(0, sip_len):  # ip is 32 bit wide
        tmp_ip = copy.deepcopy(src_ip_bin)
        tmp_ip = list(tmp_ip)
        tmp_ip[bit] = negate_bit(tmp_ip[bit])
        new_ip = ''.join(tmp_ip)
        # convert binary bit string to integer and right after make it hex string with padding to always make it 16-byte long
        other_src_ips.append(copy.deepcopy("{0:0{1}x}".format(int(new_ip, 2), 8)))

    n = sip_len + 1
    if int(n) > 33:
        print "Too many packets! Source IP is only 32 bits wide!"
        return

    print "The following destination ports could punch a hole in megaflow cache"
    print other_dst_ports
    print "The following source IPs could punch a hole in megaflow cache"
    print other_src_ips

    created_packets=0
    num_packets = int(ttl) * n
    print "Number of packets to be generated: {}".format(num_packets)
    # #ttl trick
    for t in range(0, int(ttl)):
        BASE_TTL = BASE_TTL + 1

        for i in range(0, n):
            created_packets+=1
            # print created_packets

            calculateRemainingPercentage(created_packets, num_packets)

            # first we put one package into the file whose destination port number is $dp
            # update ethernet header
            eth_header = dst_mac + ' ' + src_mac + "0800"
            # update ip header
            ip_header = ('45'
                         '00'
                         'XX XX'
                         '00 00'
                         '40 00 TT'
                         '11'
                         'YY YY')

            ip_header = ip_header.replace('TT', "%02x" % BASE_TTL)

            ip_header += other_src_ips[i]
            ip_header += dst_ip

            for pktSize in packet_sizes:
                message = getMessage(pktSize)
                # src port
                udp = udp_header.replace('ZZ ZZ', "%04x" % sport)
                # dst port
                for jj in range(0, dport_len + 1):
                    # update ports
                    new_udp = udp.replace('XX XX', "%04x" % other_dst_ports[jj])

                    udp_len = getByteLength(message) + getByteLength(udp_header)
                    new_udp = new_udp.replace('YY YY', "%04x" % udp_len)

                    ip_len = udp_len + getByteLength(ip_header)
                    ip = ip_header.replace('XX XX', "%04x" % ip_len)
                    checksum = ip_checksum(ip.replace('YY YY', '00 00'))
                    ip = ip.replace('YY YY', "%04x" % checksum)

                    pcap_len = ip_len + getByteLength(eth_header)
                    hex_str = "%08x" % pcap_len
                    reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
                    pcaph = pcap_packet_header.replace('XX XX XX XX', reverse_hex_str)
                    pcaph = pcaph.replace('YY YY YY YY', reverse_hex_str)

                    if i == 0 and jj == 0 and t == 0:
                        bytestring = pcap_global_header + pcaph + eth_header + ip + new_udp + message
                    else:
                        bytestring = pcaph + eth_header + ip + new_udp + message

                    writeByteStringToFile(bytestring, pcapfile + str(".%dbytes.pcap" % pktSize))


def generateHolePunchSPDP(pcapfile, sp, dp, ttl):
    '''
    :param pcapfile: filename
    :param n: number of packets
    :param dp: destination port
    :param sp: source port
    :return:
    '''
    global BASE_TTL

    src_ip = parseIP(default_sip)   #10.0.0.1
    dst_ip = parseIP(default_dip)   #10.0.0.2
    # print dst_ip
    src_mac = parseMAC(default_smac)
    dst_mac = parseMAC(default_dmac)

    # get the binary representation
    sport = '{0:016b}'.format(int(sp))
    dport = '{0:016b}'.format(int(dp))
    # int(dport,2) will convert it back to decimal

    # generate all other ports from dport by negating bits from left to right
    other_dst_ports = list()

    dport_len = len(dport)
    for bit in range(0, dport_len): #port is 16 bit wide
        tmp_port = copy.deepcopy(dport)
        tmp_port = list(tmp_port)
        tmp_port[bit]=negate_bit(tmp_port[bit])
        new_port = ''.join(tmp_port)
        other_dst_ports.append(copy.deepcopy(int(new_port,2)))
    other_dst_ports.append(int(dp))

    other_src_ports = list()
    sport_len = len(sport)
    for bit in range(0, sport_len): #port is 16 bit wide
        tmp_port = copy.deepcopy(sport)
        tmp_port = list(tmp_port)
        tmp_port[bit] = negate_bit(tmp_port[bit])
        new_port = ''.join(tmp_port)
        other_src_ports.append(copy.deepcopy(int(new_port, 2)))
    other_src_ports.append(int(sp))

    print "The following destination ports could punch a hole in megaflow cache"
    print other_dst_ports
    print "The following source ports could punch a hole in megaflow cache"
    print other_src_ports

    n = dport_len+1
    if n > 17:
        print "Too many packets! Destination port number is only 16 bits wide!"
        return

    created_packets=0
    num_packets = n*n*int(ttl)
    print "Number of packets to be generated: {}".format(num_packets)
    # #ttl trick
    for t in range(0, int(ttl)):
        BASE_TTL = BASE_TTL + 1

        for i in range(0, n):
            created_packets+=1
            # print created_packets

            calculateRemainingPercentage(created_packets, num_packets)

            # first we put one package into the file whose destination port number is $dp
            # update ethernet header
            eth_header = dst_mac + ' ' + src_mac + "0800"
            # update ip header
            ip_header = ('45'
                         '00'
                         'XX XX'
                         '00 00'
                         '40 00 TT'
                         '11'
                         'YY YY')

            ip_header = ip_header.replace('TT', "%02x" % BASE_TTL)
            ip_header += src_ip
            ip_header += dst_ip

            udp = udp_header.replace('ZZ ZZ', "%04x" % other_src_ports[i])

            for pktSize in packet_sizes:
                message = getMessage(pktSize)

                for jj in range(0,(sport_len+1)):
                    # update ports
                    new_udp = udp.replace('XX XX', "%04x" % other_dst_ports[jj])

                    udp_len = getByteLength(message) + getByteLength(udp_header)
                    new_udp = new_udp.replace('YY YY', "%04x" % udp_len)

                    ip_len = udp_len + getByteLength(ip_header)
                    ip = ip_header.replace('XX XX', "%04x" % ip_len)
                    checksum = ip_checksum(ip.replace('YY YY', '00 00'))
                    ip = ip.replace('YY YY', "%04x" % checksum)

                    pcap_len = ip_len + getByteLength(eth_header)
                    hex_str = "%08x" % pcap_len
                    reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
                    pcaph = pcap_packet_header.replace('XX XX XX XX', reverse_hex_str)
                    pcaph = pcaph.replace('YY YY YY YY', reverse_hex_str)

                    if t == 0 and jj == 0 and i == 0:
                        bytestring = pcap_global_header + pcaph + eth_header + ip + new_udp + message
                    else:
                        bytestring = pcaph + eth_header + ip + new_udp + message

                    writeByteStringToFile(bytestring, pcapfile + str(".%dbytes.pcap" % pktSize))


def generateHolePunchSIPSPDP(pcapfile, sip, sp, dp, ttl):
    '''
    :param pcapfile: filename
    :param n: number of packets
    :param dp: destination port
    :param sp: source port
    :param sip: source IP
    :return:
    '''
    global BASE_TTL

    src_ip = parseIP(sip)
    src_ip_bin='{0:032b}'.format(int(src_ip,16)) #convert hex to int and then to bin string
    dst_ip = parseIP(default_dip)
    # print dst_ip
    src_mac = parseMAC(default_smac)
    dst_mac = parseMAC(default_dmac)

    # get the binary representation
    sport = '{0:016b}'.format(int(sp))
    dport = '{0:016b}'.format(int(dp))
    # int(dport,2) will convert it back to decimal

    # generate all other ports from dport by negating bits from left to right
    other_dst_ports = list()

    dport_len = len(dport)
    for bit in range(0,dport_len): #port is 16 bit wide
        tmp_port = copy.deepcopy(dport)
        tmp_port = list(tmp_port)
        tmp_port[bit]=negate_bit(tmp_port[bit])
        new_port = ''.join(tmp_port)
        other_dst_ports.append(copy.deepcopy(int(new_port,2)))
    #append the set DP to the list
    other_dst_ports.append(int(dp))


    other_src_ports = list()
    sport_len = len(sport)
    for bit in range(0, sport_len): #port is 16 bit wide
        tmp_port = copy.deepcopy(sport)
        tmp_port = list(tmp_port)
        tmp_port[bit] = negate_bit(tmp_port[bit])
        new_port = ''.join(tmp_port)
        other_src_ports.append(copy.deepcopy(int(new_port, 2)))
    #append the set DP to the list
    other_src_ports.append(int(sp))

    #generate all IPs with only 1 bit difference
    other_src_ips = list()
    other_src_ips.append(src_ip)
    sip_len = 32
    print "sip_len: {}".format(sip_len)
    for bit in range(0, sip_len): #ip is 32 bit wide
        tmp_ip = copy.deepcopy(src_ip_bin)
        tmp_ip = list(tmp_ip)
        tmp_ip[bit] = negate_bit(tmp_ip[bit])
        new_ip = ''.join(tmp_ip)
        #convert binary bit string to integer and right after make it hex string with padding to always make it 16-byte long
        other_src_ips.append(copy.deepcopy("{0:0{1}x}".format(int(new_ip,2),8)))

    n = sip_len+1
    if int(n) > 33:
        print "Too many packets! Source IP is only 32 bits wide!"
        return

    print "The following destination ports could punch a hole in megaflow cache"
    print other_dst_ports
    print "The following source ports could punch a hole in megaflow cache"
    print other_src_ports
    print "The following source IPs could punch a hole in megaflow cache"
    print other_src_ips

    created_packets=0
    num_packets = n*sport_len*dport_len*int(ttl)
    print "Number of packets to be generated: {}".format(num_packets)
    # #ttl trick
    for t in range(0, int(ttl)):
        BASE_TTL = BASE_TTL + 1

        for i in range(0, n):
            created_packets+=1
            # print created_packets

            calculateRemainingPercentage(created_packets, num_packets)

            # first we put one package into the file whose destination port number is $dp
            # update ethernet header
            eth_header = dst_mac + ' ' + src_mac + "0800"
            # update ip header
            ip_header = ('45'
                         '00'
                         'XX XX'
                         '00 00'
                         '40 00 TT'
                         '11'
                         'YY YY')

            ip_header = ip_header.replace('TT', "%02x" % BASE_TTL)
            ip_header += other_src_ips[i]
            ip_header += dst_ip


            for pktSize in packet_sizes:
                message = getMessage(pktSize)
                #src port
                for j in range(0,sport_len+1):
                    udp = udp_header.replace('ZZ ZZ', "%04x" % other_src_ports[j])
                    #dst port
                    for jj in range(0,dport_len+1):
                        # update ports
                        new_udp = udp.replace('XX XX', "%04x" % other_dst_ports[jj])

                        udp_len = getByteLength(message) + getByteLength(udp_header)
                        new_udp = new_udp.replace('YY YY', "%04x" % udp_len)

                        ip_len = udp_len + getByteLength(ip_header)
                        ip = ip_header.replace('XX XX', "%04x" % ip_len)
                        checksum = ip_checksum(ip.replace('YY YY', '00 00'))
                        ip = ip.replace('YY YY', "%04x" % checksum)

                        pcap_len = ip_len + getByteLength(eth_header)
                        hex_str = "%08x" % pcap_len
                        reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
                        pcaph = pcap_packet_header.replace('XX XX XX XX', reverse_hex_str)
                        pcaph = pcaph.replace('YY YY YY YY', reverse_hex_str)

                        if j == 0 and i == 0 and jj == 0 and t == 0:
                            bytestring = pcap_global_header + pcaph + eth_header + ip + new_udp + message
                        else:
                            bytestring = pcaph + eth_header + ip + new_udp + message

                        writeByteStringToFile(bytestring, pcapfile + str(".%dbytes.pcap" % pktSize))


def generateHolePunchSIPDIPDP(pcapfile, sip, dip, dp, ttl):
    '''
    :param pcapfile: filename
    :param dp: destination port
    :param sip: source IP
    :param dip: destination IP
    :return:
    '''
    global BASE_TTL

    src_mac = parseMAC(default_smac)
    dst_mac = parseMAC(default_dmac)

    src_ip = parseIP(sip)
    src_ip_bin='{0:032b}'.format(int(src_ip,16)) #convert hex to int and then to bin string
    dst_ip = parseIP(dip)   #10.0.0.2
    dst_ip_bin='{0:032b}'.format(int(dst_ip,16)) #convert hex to int and then to bin string

    # get the binary representation
    sport = default_sp
    dport = '{0:016b}'.format(int(dp))
    # int(dport,2) will convert it back to decimal

    # generate all other ports from dport by negating bits from left to right
    other_dst_ports = list()
    dport_len = len(dport)
    for bit in range(0,dport_len): #port is 16 bit wide
        tmp_port = copy.deepcopy(dport)
        tmp_port = list(tmp_port)
        tmp_port[bit]=negate_bit(tmp_port[bit])
        new_port = ''.join(tmp_port)
        other_dst_ports.append(copy.deepcopy(int(new_port,2)))
    #append the set DP to the list
    other_dst_ports.append(int(dp))

    #generate all IPs with only 1 bit difference
    other_src_ips = list()
    sip_len = 32
    for bit in range(0, sip_len): #ip is 32 bit wide
        tmp_ip = copy.deepcopy(src_ip_bin)
        tmp_ip = list(tmp_ip)
        tmp_ip[bit] = negate_bit(tmp_ip[bit])
        new_ip = ''.join(tmp_ip)
        #convert binary bit string to integer and right after make it hex string with padding to always make it 8-bit long
        other_src_ips.append(copy.deepcopy("{0:0{1}x}".format(int(new_ip,2),8)))
    #append the set SIP to the list
    other_src_ips.append(src_ip)

    other_dst_ips = list()
    dip_len = 32
    for bit in range(0, dip_len):  # ip is 32 bit wide
        tmp_ip = copy.deepcopy(dst_ip_bin)
        tmp_ip = list(tmp_ip)
        tmp_ip[bit] = negate_bit(tmp_ip[bit])
        new_ip = ''.join(tmp_ip)
        # convert binary bit string to integer and right after make it hex string with padding to always make it 8-bit long
        other_dst_ips.append(copy.deepcopy("{0:0{1}x}".format(int(new_ip, 2), 8)))
    #append the set SIP to the list
    other_dst_ips.append(dst_ip)

    n = dip_len+1
    if n > 33:
        print "Too many packets! Destination IP is only 32 bits wide!"
        return

    print "The following destination ports could punch a hole in megaflow cache"
    print other_dst_ports
    print "The following source IPs could punch a hole in megaflow cache"
    print other_src_ips
    print "The following destination IPs could punch a hole in megaflow cache"
    print other_dst_ips

    created_packets=0
    num_packets = n*(sip_len+1)*(dport_len+1)*int(ttl)
    print "Number of packets to be generated: {}".format(num_packets)
    # #ttl trick
    for t in range(0, int(ttl)):
        BASE_TTL = BASE_TTL + 1

        for i in range(0, n):
            created_packets+=1

            calculateRemainingPercentage(created_packets, num_packets)

            # first we put one package into the file whose destination port number is $dp
            # update ethernet header
            eth_header = dst_mac + ' ' + src_mac + "0800"
            # update ip header
            ip_header = ('45'  # IP version and header length (multiples of 4 bytes)
                         '00'
                         'XX XX'  # Length - will be calculated and replaced later
                         '00 00'
                         '40 00 TT'
                         '11'  # Protocol (0x11 = UDP)
                         'YY YY'  # Checksum - will be calculated and replaced later
                         'KKKKKKKK'  # Source IP (Default: 10.0.0.1)
                         'LLLLLLLL') # Destination IP

            ip_header = ip_header.replace('TT', "%02x" % BASE_TTL)

            ip_header = ip_header.replace('LLLLLLLL', other_dst_ips[i])

            for pktSize in packet_sizes:
                message = getMessage(pktSize)

                #src_ip
                for j in range(0, sip_len+1):
                    new_ip_header=ip_header.replace('KKKKKKKK', other_src_ips[j])

                    udp = udp_header.replace('ZZ ZZ', "%04x" % sport)
                    #dst port
                    for jjj in range(0, dport_len+1):
                        # update ports
                        new_udp = udp.replace('XX XX', "%04x" % other_dst_ports[jjj])

                        udp_len = getByteLength(message) + getByteLength(udp_header)
                        new_udp = new_udp.replace('YY YY', "%04x" % udp_len)

                        ip_len = udp_len + getByteLength(new_ip_header)
                        ip = new_ip_header.replace('XX XX', "%04x" % ip_len)
                        checksum = ip_checksum(ip.replace('YY YY', '00 00'))
                        ip = ip.replace('YY YY', "%04x" % checksum)

                        pcap_len = ip_len + getByteLength(eth_header)
                        hex_str = "%08x" % pcap_len
                        reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
                        pcaph = pcap_packet_header.replace('XX XX XX XX', reverse_hex_str)
                        pcaph = pcaph.replace('YY YY YY YY', reverse_hex_str)

                        if j == 0 and i == 0 and jjj==0 and t == 0:
                            bytestring = pcap_global_header + pcaph + eth_header + ip + new_udp + message
                        else:
                            bytestring = pcaph + eth_header + ip + new_udp + message

                        writeByteStringToFile(bytestring, pcapfile + str(".%dbytes.pcap" % pktSize))


def generateHolePunchDIPSIPSPDP(pcapfile, sip, dip, sp, dp, ttl):
    '''
    :param pcapfile: filename
    :param n: number of packets
    :param dp: destination port
    :param sp: source port
    :param sip: source IP
    :param dip: destination IP
    :return:
    '''
    global BASE_TTL



    src_mac = parseMAC(default_smac)
    dst_mac = parseMAC(default_dmac)

    src_ip = parseIP(sip)
    src_ip_bin='{0:032b}'.format(int(src_ip,16)) #convert hex to int and then to bin string
    dst_ip = parseIP(dip)   #10.0.0.2
    dst_ip_bin='{0:032b}'.format(int(dst_ip,16)) #convert hex to int and then to bin string

    # get the binary representation
    sport = '{0:016b}'.format(int(sp))
    dport = '{0:016b}'.format(int(dp))
    # int(dport,2) will convert it back to decimal

    # generate all other ports from dport by negating bits from left to right
    other_dst_ports = list()
    dport_len = len(dport)
    for bit in range(0,dport_len): #port is 16 bit wide
        tmp_port = copy.deepcopy(dport)
        tmp_port = list(tmp_port)
        tmp_port[bit]=negate_bit(tmp_port[bit])
        new_port = ''.join(tmp_port)
        other_dst_ports.append(copy.deepcopy(int(new_port,2)))
    #append the set DP to the list
    other_dst_ports.append(int(dp))

    other_src_ports = list()
    sport_len = len(sport)
    for bit in range(0, sport_len): #port is 16 bit wide
        tmp_port = copy.deepcopy(sport)
        tmp_port = list(tmp_port)
        tmp_port[bit] = negate_bit(tmp_port[bit])
        new_port = ''.join(tmp_port)
        other_src_ports.append(copy.deepcopy(int(new_port, 2)))
    #append the set DP to the list
    other_src_ports.append(int(sp))

    #generate all IPs with only 1 bit difference
    other_src_ips = list()

    sip_len = 32
    for bit in range(0, sip_len): #ip is 32 bit wide
        tmp_ip = copy.deepcopy(src_ip_bin)
        tmp_ip = list(tmp_ip)
        tmp_ip[bit] = negate_bit(tmp_ip[bit])
        new_ip = ''.join(tmp_ip)
        #convert binary bit string to integer and right after make it hex string with padding to always make it 8-bit long
        other_src_ips.append(copy.deepcopy("{0:0{1}x}".format(int(new_ip,2),8)))
    #append the set SIP to the list
    other_src_ips.append(src_ip)

    other_dst_ips = list()
    dip_len = 32
    for bit in range(0, dip_len):  # ip is 32 bit wide
        tmp_ip = copy.deepcopy(dst_ip_bin)
        tmp_ip = list(tmp_ip)
        tmp_ip[bit] = negate_bit(tmp_ip[bit])
        new_ip = ''.join(tmp_ip)
        # convert binary bit string to integer and right after make it hex string with padding to always make it 8-bit long
        other_dst_ips.append(copy.deepcopy("{0:0{1}x}".format(int(new_ip, 2), 8)))
    #append the set SIP to the list
    other_dst_ips.append(dst_ip)

    n = dip_len+1
    if n > 33:
        print "Too many packets! Destination IP is only 32 bits wide!"
        return

    print "The following destination ports could punch a hole in megaflow cache"
    print other_dst_ports
    print "The following source ports could punch a hole in megaflow cache"
    print other_src_ports
    print "The following source IPs could punch a hole in megaflow cache"
    print other_src_ips
    print "The following destination IPs could punch a hole in megaflow cache"
    print other_dst_ips

    created_packets=0
    num_packets = n*(sip_len+1)*(dport_len+1)*(sport_len+1)*int(ttl)
    print "Number of packets to be generated: {}".format(num_packets)
    # #ttl trick
    for t in range(0, int(ttl)):
        BASE_TTL = BASE_TTL + 1

        for i in range(0, n):
            created_packets+=1

            calculateRemainingPercentage(created_packets, num_packets)

            # first we put one package into the file whose destination port number is $dp
            # update ethernet header
            eth_header = dst_mac + ' ' + src_mac + "0800"
            # update ip header
            ip_header = ('45'  # IP version and header length (multiples of 4 bytes)
                         '00'
                         'XX XX'  # Length - will be calculated and replaced later
                         '00 00'
                         '40 00 TT'
                         '11'  # Protocol (0x11 = UDP)
                         'YY YY'  # Checksum - will be calculated and replaced later
                         'KKKKKKKK'  # Source IP (Default: 10.0.0.1)
                         'LLLLLLLL') # Destination IP

            ip_header = ip_header.replace('TT', "%02x" % BASE_TTL)

            ip_header = ip_header.replace('LLLLLLLL', other_dst_ips[i])

            for pktSize in packet_sizes:
                message = getMessage(pktSize)

                #src_ip
                for j in range(0,sip_len+1):
                    new_ip_header=ip_header.replace('KKKKKKKK', other_src_ips[j])

                    #src port
                    for jj in range(0,sport_len+1):
                        udp = udp_header.replace('ZZ ZZ', "%04x" % other_src_ports[jj])
                        #dst port
                        for jjj in range(0,dport_len+1):
                            # update ports
                            new_udp = udp.replace('XX XX', "%04x" % other_dst_ports[jjj])

                            udp_len = getByteLength(message) + getByteLength(udp_header)
                            new_udp = new_udp.replace('YY YY', "%04x" % udp_len)

                            ip_len = udp_len + getByteLength(new_ip_header)
                            ip = new_ip_header.replace('XX XX', "%04x" % ip_len)
                            checksum = ip_checksum(ip.replace('YY YY', '00 00'))
                            ip = ip.replace('YY YY', "%04x" % checksum)

                            pcap_len = ip_len + getByteLength(eth_header)
                            hex_str = "%08x" % pcap_len
                            reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
                            pcaph = pcap_packet_header.replace('XX XX XX XX', reverse_hex_str)
                            pcaph = pcaph.replace('YY YY YY YY', reverse_hex_str)

                            if j == 0 and i == 0 and jj == 0 and jjj==0 and t == 0:
                                bytestring = pcap_global_header + pcaph + eth_header + ip + new_udp + message
                            else:
                                bytestring = pcaph + eth_header + ip + new_udp + message

                            writeByteStringToFile(bytestring, pcapfile + str(".%dbytes.pcap" % pktSize))


def splitN(str1,n):
    return [str1[start:start+n] for start in range(0, len(str1), n)]

#Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):

    #split into bytes
    words = splitN(''.join(iph.split()),4)

    csum = 0
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum


def getMac(mac):
  #get some random number between 1-255 for the first part of MAC (first 2 byte)
  #first_2byte=random.randrange(1,255)
  mac = str("%06x" % (mac))
  #print(mac)
  return mac

def getRandomMAC():
    return "00" + str("%0.10X" % random.randint(1,0xffffffffff))

def getRandomIP():
    return str("%0.8X" % random.randint(1,0xffffffff))

#this function gets a random vlan id in the specified range starting from 101
def getVLANid(spec_range):
    start = 100
    return random.randint(start+1, start+spec_range)

def getNextIP(nextIP, ul_dl):
    if (nextIP % 256) == 0:
        nextIP += 1
    if ul_dl:
        s_pre = "0A"
    else:
        s_pre = "AA"

    s = s_pre + str("%0.6X" % nextIP)

    return s

def getRandomPort():
    port = random.randint(1,65535)
    if(port == 4305):
        getRandomPort()
    return int(port)


def parseMAC(mac):
    ret_val=mac.replace(":","").upper()
    if len(ret_val) != 12: #check mac address length
        print "ERROR during parsing mac address - not long enough!: {}".format(mac)
        exit(-1)
    return  ret_val

def parseIP(ip):
    ret_val = ""
    #split IP address into 4 8-bit values
    ip_segments=ip.split(".")
    for i in ip_segments:
        ret_val+=str("%0.2X" % int(i))
    if len(ret_val) != 8: #check length of IP
        print "ERROR during parsing IP address - not long enough!: {}".format(ip)
        exit(-1)
    return ret_val


def writeoutLine(filename, line):
    file = open(filename, 'a')
    file.write(line + "\n")
    file.close()

def getMessage(packetsize):
    message = ''
    for i in range(0,int(packetsize)-46): # 46 = eth + ip + udp header
        message += "%0.2X " % random.randint(0,255)

    return message

"""------------------------------------------"""
""" End of functions, execution starts here: """
"""------------------------------------------"""



parser = argparse.ArgumentParser(description="Usage of PCAP generator for hole punching",
                                 usage="python pcap_generator_for_holepunch.py -t TYPE -o OUTPUT <other options>",
                                 formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-t','--type',nargs=1,
                    help=textwrap.dedent('''\
                         Specify the type: DP, SP_DP, DIP_SP_DP, SIP_DIP_SP_DP.
                         \033[1mDP\033[0m will punch a hole only on the dst_port (udp) -> 17 packets!
                         \033[1mSP_DP\033[0m will punch holes on dst_port (UDP) and src_port (UDP) -> 17x17 packets
                         \033[1mSIP_DP\033[0m will punch holes on dst_port (UDP) and src_ip -> 17x33 packets
                         \033[1mSIP_SP_DP\033[0m will punch holes on dst_port (UDP), src_port (UDP) and dst_ip -> 17x17x33 packets
                         \033[1mSIP_DIP_DP\033[0m will punch holes on dst_port (UDP), dst_ip and src_ip -> 17x33x33
                         \033[1mSIP_DIP_SP_DP\033[0m will punch holes on dst_port (UDP), src_port (UDP), dst_ip and src_ip -> 17x17x33x33 packets'''),
                    required=True)
parser.add_argument('-o','--output',nargs=1,
                    help="Specify the output PCAP file's basename! "
                         "Output will be [output].[PACKETSIZE]bytes.pcap extension is not needed!",
                    required=True)
# parser.add_argument('-p','--packetsizes',nargs=1,
#                     help="Specify here the required packetsize! "
#                     "In case of more than one, just create a comma separated list "
#                     "such as 64,112,42. Default: 64",
#                     required=False,
#                     default=[64])
parser.add_argument('-a','--src_mac',nargs=1,
                    help="Specify default source MAC address (for all packets), if not set "
                    "default is 00:00:00:00:00:01",
                    required=False,
                    default=["00:00:00:00:00:01"])
parser.add_argument('-b', '--dst_mac', nargs=1,
                    help="Specify default source MAC address (for all packets), if not set "
                         "default is 00:00:00:00:00:02",
                    required=False,
                    default=["00:00:00:00:00:02"])
parser.add_argument('-c', '--src_ip', nargs=1,
                    help="Specify src_ip for hole punching, if not set "
                         "the default hole is 10.0.0.1",
                    required=False,
                    default=["10.0.0.1"])
parser.add_argument('-d', '--dst_ip', nargs=1,
                    help="Specify dst_ip for hole punching, if not set "
                         "the default hole is 10.0.0.2",
                    required=False,
                    default=["10.0.0.2"])

parser.add_argument('-e', '--src_port', nargs=1,
                    help="Specify src_port for hole punching, if not set "
                         "the default hole is 12345",
                    required=False,
                    default=["12345"])
parser.add_argument('-f', '--dst_port', nargs=1,
                    help="Specify dst_port for hole punching, if not set "
                         "the default hole is 80",
                    required=False,
                    default=["80"])
parser.add_argument('-g', '--ttl', nargs=1,
                    help="Specify how many different TTLs you want to have in the packets"
                         "(multiplying the base number of packets by this number, e.g., in case"
                         "of number 2 and type DP, the number of packet will be 17*2). If not set "
                         "the default number is 1",
                    required=False,
                    default=["1"])


args = parser.parse_args()

type = args.type[0]
types = ['DP', 'SP_DP', 'SIP_DP', 'SIP_DIP_DP', 'SIP_SP_DP','SIP_DIP_SP_DP']

if type not in types:
    print "Type has not set properly. Accepted fields: DP, SP_DP, SIP_DP, SIP_DIP_DP, SIP_SP_DP, SIP_DIP_SP_DP"
    exit(-1)


output = args.output[0]
default_smac = args.src_mac[0]
default_dmac = args.dst_mac[0]
default_sip = args.src_ip[0]
default_dip = args.dst_ip[0]
default_sp = int(args.src_port[0])
default_dp = int(args.dst_port[0])
default_ttl = int(args.ttl[0])



for i in packet_sizes:
    open(str("%s.%dbytes.pcap" % (output,i)),'w') # delete contents


if type == "DP":
    generateHolePunchDP(output, default_dp, default_ttl)
elif type == "SP_DP":
    generateHolePunchSPDP(output, default_sp, default_dp, default_ttl)
elif type == "SIP_DP":
    generateHolePunchSIPDP(output, default_sip, default_dp, default_ttl)
elif type == "SIP_SP_DP":
    generateHolePunchSIPSPDP(output, default_sip, default_sp, default_dp, default_ttl)
elif type == "SIP_DIP_DP":
    generateHolePunchSIPDIPDP(output, default_sip, default_dip, default_dp, default_ttl)
elif type == "SIP_DIP_SP_DP":
    generateHolePunchDIPSIPSPDP(output, default_sip, default_dip, default_sp, default_dp, default_ttl)


# generateHolePunchSIPSPDP(fileName, nPkts, 80, 12345, "0A000001")  #initial sip = 10.0.0.1
# generateHolePunchDIPSIPSPDP(fileName, nPkts, 80, 12345, "0A000001", "0A000002")  #initial sip = 10.0.0.1, intial dip = 10.0.0.2
