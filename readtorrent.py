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
		self.peer_id = "torentorentorentoren"

	def getinfo(self, filename):
		fp = open(filename, "rb")
		data = fp.read()	#it is string
		decode_data = bencoder.decode(data)    #get a dictionary 
		#print(decode_data)
		if 'announce-list' in decode_data and 'info' in decode_data:
			self.tracker = decode_data.get('announce')
			self.tracker_list = decode_data.get('announce-list')
			self.create = decode_data.get('created by')
			self.date = decode_data.get('creation date')
			self.source = decode_data.get('comment')
			info = decode_data.get('info')
			self.size = info.get('length')
			self.piece_size = info.get('piece length')
			self.name = info.get('name')
			self.pieces = info.get('pieces')
		else:
			print("Invalid torrent file")
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
	final_buf = struct.pack('qqqiIIih', downloaded, left, uploaded, event, ip, key, num_want, port)
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
		ip = socket.gethostbyname(urlsep.hostname)
		conn_id = 0x41727101980
		action = 0x0
		transaction_id = int(random.randrange(0, 255))
		conn_buf = struct.pack('!Qii', conn_id, action, transaction_id) #conn_id is 64bit, action and transaction_id 32 bit standard
		try:	
				
			mysocket.sendto(conn_buf, (ip, port))
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
		
		except Exception as e:
            		print(e)
            		return
		except socket.gaierror as e:
			print(e)
			return


def getpeers(mytorrent):
	peers_list = []
	for i in mytorrent.tracker_list:
		print(i)
		tracker = i[0][0:]
		if i[0][:4] == 'http':
			peers = connect_httptracker(mytorrent, tracker)
		elif i[0][:3] == 'udp':
			peers = connect_udptracker(mytorrent, tracker)
		if peers not in peers_list:
			peers_list.append(peers)
	
	if len(peers_list) != 0:
		return peers_list

def connect_handshake(peers_list, mytorrent):
	print peers_list
	for i in peers_list:
		print i
		ip = i[0]
		port = i[1]
		print ip
		print port
		peerSocket = socket.socket()
		peerSocket.connect(i[0])
		
		pstr = "BitTorrent protocol"
		pstrlen = len(pstr)
		reserved = struct.pack('!q', 0)
		message = pstrlen + pstr + reserved + mytorrent.info_hash + mytorrent.peer_id
		print(message)
		


mytorrent = readtorrent()
#print(mytorrent.tracker_list)
peers_list = getpeers(mytorrent)
print 'loop printing'
print peers_list[0][:1]
for i in peers_list:
	print i
	break
#print(peers_list)
#connect_handshake(peers_list, mytorrent)
