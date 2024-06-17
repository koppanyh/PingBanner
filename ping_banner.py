# https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf
# https://unix.stackexchange.com/questions/412446/how-to-disable-ping-response-icmp-echo-in-linux-all-the-time
# echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all  # turn ping on
# echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all  # turn ping off

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

def hexify(v):
	h = hex(v)[2:]
	if len(h) == 1:
		return "0" + h
	return h

def calculateChecksum(data):
	index = 0
	checksum = 0
	while index < len(data):
		high = data[index] << 8
		index += 1
		low = 0 if index >= len(data) else data[index]
		index += 1
		checksum += high | low
	while checksum > 0xFFFF:
		carry = checksum >> 16
		checksum &= 0xFFFF
		checksum += carry
	return checksum ^ 0xFFFF

class Stream:
	def __init__(self, data):
		self.data = data
		self.index = 0
	def readU8(self):
		val = self.data[self.index]
		self.index += 1
		return val
	def readU16(self):
		val = self.readU8() << 8
		return val | self.readU8()
	def readU32(self):
		val = self.readU16() << 16
		return val | self.readU16()

class IPHeader:
	def __init__(self, stream):
		self.version = stream.readU8()
		self.header_len = (self.version & 0x0F) * 4
		self.version >>= 4
		self.tos = stream.readU8()
		self.total_len = stream.readU16()
		self.identification = stream.readU16()
		self.frag_flags = stream.readU16()
		self.fragment = self.frag_flags & 0x1FFF
		self.frag_flags >>= 13
		self.ttl = stream.readU8()
		self.protocol = stream.readU8()
		self.checksum = stream.readU16()
		self.source_addr = stream.readU32()
		self.dest_addr = stream.readU32()
		self.options = []
		for _ in range(self.header_len - 20):
			self.options.append(stream.readU8())
		self.data = None
	def isICMP(self):
		return self.protocol == 1
	def toBytes(self):
		total_len = 20 + len(self.options) + len(self.data)
		data = [
			self.version << 4 | self.header_len >> 2,
			self.tos,
			total_len >> 8, total_len & 0xFF, #self.total_len >> 8, self.total_len & 0xFF,
			self.identification >> 8, self.identification & 0xFF,
			self.frag_flags << 5 | self.fragment >> 8, self.fragment & 0xFF,
			64, #self.ttl,
			self.protocol,
			0, 0, #self.checksum >> 8, self.checksum & 0xFF,
			self.source_addr >> 24, (self.source_addr & 0xFF0000) >> 16, (self.source_addr & 0xFF00) >> 8, self.source_addr & 0xFF,
			self.dest_addr >> 24, (self.dest_addr & 0xFF0000) >> 16, (self.dest_addr & 0xFF00) >> 8, self.dest_addr & 0xFF,
		]
		data.extend(self.options)
		data.extend(self.data)
		self.checksum = calculateChecksum(data)
		data[10] = self.checksum >> 8
		data[11] = self.checksum & 0xFF
		return data
	def __repr__(self):
		return f'IPHeader(ver:{self.version}, hln:{self.header_len}, tos:{self.tos}, tln:{self.total_len}, idn:{self.identification}, fgs:{self.frag_flags}, frg:{self.fragment}, ttl:{self.ttl}, ptc:{self.protocol}, chk:{self.checksum}, src:{self.source_addr}, dst:{self.dest_addr}, opt:{self.options}, dat:{self.data})'

class ICMPEcho:
	def __init__(self, stream):
		self.type = stream.readU8()
		self.code = stream.readU8()
		self.checksum = stream.readU16()
		self.identifier = None
		self.seq_num = None
		self.data = None
	def isEchoReq(self):
		return self.type == 8
	def finalize(self, stream, header):
		self.identifier = stream.readU16()
		self.seq_num = stream.readU16()
		self.data = []
		for _ in range(header.total_len - header.header_len - 8):
			self.data.append(stream.readU8())
	def toBytes(self):
		data = [
			self.type,
			self.code,
			0, 0, #self.checksum >> 8, self.checksum & 0xFF,
			self.identifier >> 8, self.identifier & 0xFF,
			self.seq_num >> 8, self.seq_num & 0xFF
		]
		data.extend(self.data)
		self.checksum = calculateChecksum(data)
		data[2] = self.checksum >> 8
		data[3] = self.checksum & 0xFF
		return data
	def __repr__(self):
		return f'ICMPHeader(typ:{self.type}, cod:{self.code}, chk:{self.checksum}, idn:{self.identifier}, seq:{self.seq_num}, dat:{self.data})'

#message = list(b'If you can read this, then you\'re a hacker B)')
message = list(b'1F Y0U C4N r34D 7H15 7H3N Y0Ur3 4 H4XX0r B)')

while True:
	p, i = s.recvfrom(65565)
	print()
	print(' '.join([hexify(x) for x in p]))
	stream = Stream(p)
	header = IPHeader(stream)
	print(header)
	if not header.isICMP():
		continue
	icmp = ICMPEcho(stream)
	if not icmp.isEchoReq():
		continue
	icmp.finalize(stream, header)
	print(icmp)
	icmp.type = 0
	icmp.data = message
	p = bytes(icmp.toBytes())
	#source_addr = header.source_addr
	#header.source_addr = header.dest_addr
	#header.dest_addr = source_addr
	#header.data = icmp.toBytes()
	##break
	#p = bytes(header.toBytes())
	#print(' '.join([hexify(x) for x in p]))
	#stream = Stream(p)
	#header = IPHeader(stream)
	#print(header)
	#icmp = ICMPEcho(stream)
	#icmp.finalize(stream, header)
	#print(icmp)
	print(s.sendto(p, i))

