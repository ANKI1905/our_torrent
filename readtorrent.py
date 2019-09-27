import bencoder #to bencode and decode file
import sys	#for command line args
import hashlib
import requests
import socket
import urlparse
import random
import struct
import binascii
import pickle
from socket import gaierror
class readtorrent:
	def __init__(self):
		self.tracker = ""
		self.tracker_list = ""
		self.piece_size = 0
		self.pieces = ""
		self.date = ""
		self.size = 0
		self.name = ""
		self.create = ""
		self.source = ""
		self.hash_info = ""
		self.getinfo(sys.argv[1])
		self.peer_id = "QWERTYUIOPASDFGHJKLZ"
		self.directory = " "
		self.files = []
		self. no_of_piece = 0 

	def getinfo(self, filename):
		fp = open(filename, "rb")
		data = fp.read()	#it is string
		decode_data = bencoder.decode(data)    #get a dictionary 
		#print(decode_data)
		if 'announce' in decode_data and 'info' in decode_data:
			self.tracker = decode_data.get('announce')
			self.tracker_list = decode_data.get('announce-list')
			self.create = decode_data.get('created by')
			self.date = decode_data.get('creation date')
			self.source = decode_data.get('comment')
			info = decode_data.get('info')
			self.piece_size = info.get('piece length')
			self.pieces = info.get('pieces')
		else:
			print("Invalid torrent file")
		if 'length' in info:
			self.directory = ''
			self.files = [(info.get('name'), info.get('length'))]
			self.size = info.get('length')
			self.name = info.get('name')
		else:
			files = []			
			self.directory = info.get('name')
			for d in decode_data['info']['files']:
				files.append((d['path'], d['length']))
				self.size += d['length']
		self.no_of_pieces = self.size / self.piece_size
		sha1 = hashlib.sha1()
		sha1.update(bencoder.encode(info))
		self.hash_info = sha1.digest()

def get_http_peer(peer_list):
	a = 0
	peers = []
	while a < len(peer_list):
		ip = socket.inet_ntoa(peer_list[a : a + 4])
		port = struct.unpack('!H', peer_list[a + 4 : a + 6])
		b = a + 6
		a = b
		peers.append((ip, port))
  	return peers
	

def connect_httptracker(mytorrent, tracker):
	parameters = {
		'info_hash': mytorrent.hash_info,
		'peer_id': mytorrent.peer_id,
		'uploaded': 0,
		'downloaded': 0,
		'event': "started",
		'left': mytorrent.size,
		'port': 6881,
		'compact': 1
	}
	try:
		response = requests.get(tracker, params = parameters, timeout = 5)
		responses = bencoder.decode(response.content)
		peer_list = get_http_peer(responses['peers'])
		return peer_list
	except Exception as e:
		print(e)
		return


def announce_udptracker(resp_buf, mytorrent):
	conn_id = resp_buf[8:]
	action = 1
	transaction_id = int(random.randrange(0, 1023))
	initial_buf = struct.pack('!ii', action, transaction_id)
	downloaded = 0
	left = mytorrent.size
	uploaded = 0
	event = 0
	ip = 0
	key = 0
	num_want = -1
	port = 6881
	final_buf = struct.pack('!qqqiIIih', downloaded, left, uploaded, event, ip, key, num_want, port)
	buffer_data = conn_id + initial_buf + mytorrent.hash_info + mytorrent.peer_id + final_buf
	
	return buffer_data
	

def announce_udpoutput(received):
	action = struct.unpack('!i', received[0:4])
	transaction_id = struct.unpack('!i', received[4:8])
	interval = struct.unpack('!i', received[8:12])
	leechers = struct.unpack('!i', received[12:16])
	seeders = struct.unpack('!i', received[16:20])
	a = 20
	peer_list = []

	while a < len(received):
		ip = socket.inet_ntoa(received[a : a + 4])
		port = struct.unpack('!H', received[a + 4 : a + 6])
		peer_list.append((ip, port))
		b = a + 6
		a = b
	
	return peer_list

def connect_udptracker(mytorrent, tracker):
		mysocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		mysocket.settimeout(5)
		urlsep = urlparse.urlparse(tracker)
		port = urlsep.port
		try:
			ip = socket.gethostbyname(urlsep.hostname)
		except socket.gaierror as e:
			print(e)
			return
		conn_id = 0x41727101980
		action = 0x0
		transaction_id = int(random.randrange(0, 255))
		conn_buf = struct.pack('!Qii', conn_id, action, transaction_id) 
		try:	
			print('in try')	
			mysocket.sendto(conn_buf, (ip, port))
			print('conn')
			response = mysocket.recvfrom(2048)
			print("udp")
			resp_buf = response[0]
	#		print(resp_buf)
			resp_action = struct.unpack('!i', resp_buf[ :4])
			resp_trans_id = struct.unpack('!i', resp_buf[4:8])
			resp_conn_id = struct.unpack('!Q', resp_buf[8:])
			buffer_data = announce_udptracker(resp_buf, mytorrent)
			mysocket.sendto(buffer_data, (ip, port))
			received_data = mysocket.recvfrom(2048)
			received = received_data[0]
			peers = announce_udpoutput(received)
			mysocket.close()
			return peers
		
		except socket.gaierror as e:
			print(e)
			sys.exit()

		except Exception as e:
            		print(e)
            		return

def getpeers(mytorrent):
	peers_list = []
	if mytorrent.tracker_list != None:
		for i in mytorrent.tracker_list:
			print(i)
			tracker = i[0][0:]
			if i[0][:4] == 'http':
				peers = connect_httptracker(mytorrent, tracker)
			elif i[0][:3] == 'udp':
				peers = connect_udptracker(mytorrent, tracker)
			if peers_list != None and peers != None:
				for j in peers:
					if j not in peers_list:
						peers_list.append(j)
			elif peers_list == None: 
				peers_list = peers
	
	else:
		i = mytorrent.tracker
		print i
		if i[0][:4] == 'http':
			peers = connect_httptracker(mytorrent, tracker)
		elif i[0][:3] == 'udp':
			peers = connect_udptracker(mytorrent, tracker)
		peers_list = peers
	
	print peers_list
	if len(peers_list) != 0:
		return peers_list		

def keep_alive():
	length = 0
	message = struct.pack("!i", length)
	return message
def choke():
	message_id = 0
	length = 1
	message = struct.pack('!ib', length, message_id)
	return message
def unchoke():
	message_id = 1
	length = 1
	message = struct.pack('!ib', length, message_id)
	return message
def pack_interested():
	message_id = 2
	length = 1
	message = struct.pack('!ib', length, message_id)
	print (binascii.hexlify(message))
	return message


def not_interested():
	message_id = 3
	length = 1
	message = struct.pack('!ib', length, message_id)
	return message


def unpack_unchoke(response):
	print response[0:4]
	length = response[0:4]
	message_id = response[4:5]
	print('ANKITA')
	print(length, message_id)
	return True


def pack_request(mytorrent):
	length = 13
	message_id = 6
	index = 0
	begin = 0
	if mytorrent.piece_size > 16384:
		blength = 16384
	else:
		blength = mytorrent.piece_size
	message = struct.pack('!ibiii', length, message_id, index, begin, blength)
	return message







def connect_handshake(peers_list, mytorrent):
	for i in peers_list:
		ip = i[0]
		port = i[1][-1]
		peerSocket = socket.socket()
		peerSocket.settimeout(5)
		try:			
			peerSocket.connect((ip, port))
			print(ip, port)
			print('CONNECTION')
		except Exception as e:
			print (e) 
			pass
		
		pstr = b"BitTorrent protocol"
		pstrlen = chr(len(pstr))
		reserved = "\x00\x00\x00\x00\x00\x00\x00\x00"
		message = pstrlen + pstr + reserved + mytorrent.hash_info + mytorrent.peer_id
		#print(message)
		try:			
			peerSocket.send(message)
			print('SENd')
		except Exception as e:
			print (e) 
			pass
		response_ =[]
		try:			
			response_ = peerSocket.recv(2048)
			'''a = len(message)
			print a
			print(len(response_))
			response = response_[len(message) :]
			print(len(response))
			print response
			if len(response) > 0:
				length_prefix = struct.unpack('!i',response[0 : 4])
				bitlength = length_prefix - 1
				print length_prefix
				id_ = struct.unpack('!B', response[4:5])
				print id_
				b = 5
				bitfield = response[5 : ]
				print(bitfield)
				print(bitfield.decode())'''
		except Exception as e:
			print (e) 
			pass
		response = response_[len(message) :]
		if len(response) > 0:
			length_prefix = struct.unpack('!i',response[0 : 4])
			id_ = struct.unpack('!B', response[4:5])
			blength = length_prefix[0] - 1
			b = 5
			bitfield = response[5 : blength + 5 ]
			bytestring = binascii.hexlify(bitfield)
			print(" ".join([bytestring[i:i+2] for i in range(0, len(bytestring), 2)]))
			if len(bitfield) == blength:
				intrst = pack_interested()
				try:
					peerSocket.send(intrst)
					rsponse = peerSocket.recv(2048)
					print(len(rsponse))
					b = unpack_unchoke(rsponse)
					if b:
						try:
							print 'SEND REQ'
							peerSocket.send(pack_request(mytorrent))
							rp = peerSocket.recv(2048)
							print rp
							print('MESSAGE')
							print (struct.unpack('!i',rp [0:4]))
							print (struct.unpack('!b', rp[4:5]))
							print rp[5:]
						except:
							pass
						
				except:
					pass
				


		
		peerSocket.close()
		


mytorrent = readtorrent()
#print(mytorrent.tracker_list)
peers_list = getpeers(mytorrent)

#print(peers_list)
connect_handshake(peers_list, mytorrent)
