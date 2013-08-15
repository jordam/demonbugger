import thread
import pcap, dpkt
import socket

import os.path
import sys
import argparse
import subprocess

def sniff(args):
	custfind = []
	for cmd in args.cmdhex:
		custfind.append(cmd.decode('hex'))
	seen = {}
	pc = pcap.pcap()
	pc.setfilter('udp and port ' + str(int(args.port)))
	for ts, pkt in pc:
		packet = dpkt.ethernet.Ethernet(pkt)
		pdat = str(packet.data)[28:]
		phead = str(packet.data)[0:27]
		if args.nmac or not str(phead[0:6]) in args.macs:
			if args.dpings and len(str(packet.data)) == 57 and pdat[0:3] == '\x0d\x02\x00':
				parseping(packet, 'ping request', args)

			if args.dpingreps and len(str(packet.data)) == 57 and pdat[0:3] == '\x0c\x02\x00':
				parseping(packet, 'ping response', args)
			
			if args.dconnect1 and pdat[0:3] == '\x01\x02\x00':
				parsepacket(packet, 'connect1',  args)

			if args.ddata and pdat[0:2] == '\x06\x02':
				parsepacket(packet, 'data', args)
			
			if len(custfind) and pdat[0] in custfind:
				parsepacket(packet, 'Cx'+pdat[0].encode('hex'), args)

seen = {}
def parsepacket(packet, ptype, args):
	global seen
	bs = ptype + " "
	dip = socket.inet_ntoa(str(packet.data.dst))
	sip = socket.inet_ntoa(str(packet.data.src))
	sort = dip
	if args.ss:
		sort = sip
	if args.v >0 or not sort in seen:
		bs += "(S)" + sip + ' '
		bs += "(T)" + dip + ' '
		seen[dip] = 1
	if args.v > 2:
		bs += 'HEADER: ' + str(packet.data)[0:27].encode('hex') + ' '
	if args.v > 1:
		bs += 'PAYLOAD: ' + str(packet.data)[28:].encode('hex') + ' '

	if bs != ptype + " ":
		print bs

seenpings = {}
def parseping(packet, ptype, args):
	global seenpings
	bs = ptype + " "
	pdat = str(packet.data)[28:]
	dip = socket.inet_ntoa(str(packet.data.dst))
	sip = socket.inet_ntoa(str(packet.data.src))
	sort = dip
        if args.ss:
                sort = sip
	magic = pdat[13:17].encode('hex')
	if args.v >0 or not (sort + magic) in seenpings:
		seenpings[(sort + magic)] = [sort, magic]
		bs += "(S)" + sip + ' '
                bs += "(T)" + dip + ' '
	if args.v > 2:
                bs += 'HEADER: ' + str(packet.data)[0:27].encode('hex') + ' '
        if args.v > 1:
                bs += 'PAYLOAD: ' + str(packet.data)[28:].encode('hex') + ' '
	if bs != ptype + " ":
		print bs
		sid = pdat[3:13].encode('hex')
		sintip = socket.inet_ntoa(pdat[17:21])
		textip = socket.inet_ntoa(pdat[23:27])
		print bs + "{"
		print "\t(T)MAGIC: " + magic
		print "\t(S)ID: " + sid
		print "\t(S)INTERNAL IP: " + sintip
		print "\t(t)EXTERNAL IP: " + textip
		print "}"

def run_command(command):
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
			 shell=True)
    return iter(p.stdout.readline, b'')

def main(args=None):
    if args is None:
        args = sys.argv

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument("-p", dest="port", default="3074",
		      help="Sniffing Port")
    parser.add_argument("-v",
                      action="store", dest="v", default='0',
                      help="Verbosity, 0 (default, display ip's matching packets once) 1 (display all matching ips), 2 (dump packet payload), 3 (dump full packet)")
    parser.add_argument("-sm",
                      action="store_true", dest="ss", default=False,
                      help="set ip matching to source rather then destination")
    parser.add_argument("-Xmac",
                      action="store_true", dest="nmac", default=False,
                      help="dont filter the mac address of this computer from packets")
    parser.add_argument("-dp",
                      action="store_true", dest="dpings", default=False,
                      help="display ping requests")
    parser.add_argument("-dpr",
                      action="store_true", dest="dpingreps", default=False,
                      help="display ping responses")
    parser.add_argument("-dc",
                      action="store_true", dest="dconnect1", default=False,
                      help="display first connection packet")
    parser.add_argument("-dd",
                      action="store_true", dest="ddata", default=False,
                      help="display data packets")
    parser.add_argument("-dC",
                      action="append", dest="cmdhex", default=[],
                      help="display packets with command (CMDHEX)")

    args = parser.parse_args()
    #print args
    args.v = int(args.v)
    args.port = int(args.port)
    macs = []
    if not args.nmac:
	    for line in run_command("""ifconfig | grep HWaddr |cut -dH -f2|cut -d\  -f2"""):
		#print line
		macs += (''.join((line.strip()).split(':'))).decode('hex')
	    if not len(macs):
		print "MAC FIND FAILURE"
		print "might not be able to filter out replay packets"
    args.macs = macs
    
    sniff(args)

    # return > 0 for errors

if __name__ == "__main__":
    sys.exit(main())
