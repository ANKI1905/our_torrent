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
import bitstring
import time
import os
from tqdm import tqdm
#from thread import *
import threading
#from thread import *
from socket import gaierror
BLOCK_SIZE = 16384 #16kb 2 ** 14
thread_list = []
pieces_list = [] 
all_piece = 0
pieces = '0' * 1000
lock = threading.Lock()
class Piece:
	def __init__(self, mytorrent, i):
		self.piece_no = i
		self.piece_length = 0
		self.piece_hash = " "
		self.piece_downloaded = False
		self.piece_downloading = False
		self.nos_of_blocks = 0
		self.piece_data = " "
		self.peers = []
		self.nos_of_peers = 0
		self.data = ""
		self.get_info(mytorrent, i)

		self.blocks_list = []
		self.get_blocks()

	def get_info(self, mytorrent, i):
		first = i * 20
		last = first + 20
		self.piece_hash = mytorrent.pieces[first : last]
		if i < mytorrent.no_of_pieces - 1:
			self.piece_length = mytorrent.piece_size
		else:
			self.piece_length = mytorrent.piece_size - (mytorrent.size % mytorrent.piece_size)

		
		if self.piece_length <= BLOCK_SIZE:
			self.nos_of_blocks = 1
		else:
			if self.piece_length % BLOCK_SIZE != 0:
				extra = 1
			else:
				extra = 0
			
			self.nos_of_blocks = self.piece_length / BLOCK_SIZE + extra

	def get_blocks(self):
		for i in range(self.nos_of_blocks):
			block = Block(i, self.piece_no, self.nos_of_blocks)
			#block.get_size(self)
			self.blocks_list.append(block)


class Block:
	def __init__(self, i, piece_number, blocks):
		self.piece_no = piece_number
		self.block_no = i
		self.block_size = BLOCK_SIZE
		self.downloaded = False
		self.downloading = False

		
		
class Peer:
	def __init__(self, mytorrent, ip, port):
        	self.handshaked = False
		self.have_piece = False
		self.connected = False
		self.read_buffer = ''
		self.buffer_data = ''
		self.socket = None
		self.ip = ip
		self.port = port
		self.have_pieces = []
		self.nos_of_pieces = mytorrent.no_of_pieces
		self.bit_field = bitstring.BitArray(mytorrent.no_of_pieces)
		self.unchoke = False
		self.choke = False 
		self.id = ""
		self.data = ""
		self.get_connected()
	
	def get_connected(self):
		try:
			self.socket = socket.create_connection((self.ip, self.port), timeout = 5)
			self.connected = True
			#print 'connection_successful'
		except:
			pass

	def get_handshake(self, mytorrent):
		try:
			message = handshake(mytorrent)
#			print message
			self.socket.send(message)
			#print 'message send'
			response_ = self.socket.recv(2048)
			response = response_[len(message) :]
#			print response
			if len(response) > 5:
				length_prefix = struct.unpack('!I',response[0 : 4])
				id_ = struct.unpack('!B', response[4:5])
				blength = length_prefix[0] - 1
				b = 5
				rsp = response[5 :]
				bitfield = response[5 : blength + 5]
				#print (binascii.hexlify(rsp))
				self.read_buffer = bitstring.BitArray(hex = binascii.hexlify(bitfield)).bin
#				print self.read_buffer
				self.handshaked = True
#				print(self.read_buffer) 
				if len(response[blength + 5 : ])> 0:
					mesge = binascii.hexlify(response[blength + 5 : ])
					print mesge
					a = 0
					while a < len(mesge):
						state, number = unpack_data_hshake(mesge[a : a + 18])
				#		print state, number
						if state == 'have':
							self.have_pieces.append(number)
#							print self.have_pieces
						elif state == 'unchoke':
#							print 'in unchoke'
							self.unchoke = True
						elif state == 'choke':
							self.choke = True
						a+=18
		except:
			pass
				

			
class readtorrent:
	def __init__(self):
		self.tracker = ""
		self.tracker_list = ""
		self.piece_size = 0
		self.no_of_pieces = 0
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
	def getinfo(self, filename):
		fp = open(filename, "rb")
		data = fp.read()	#it is string
		#print data		
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
			#print("Invalid torrent file")
			pass
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
		
		if self.size % self.piece_size != 0:
			extra = 1
#			print 'extra 1'
		else: 
			extra = 0
#			print 'extra 2'
		
		self.no_of_pieces = self.size / self.piece_size + extra
#		print self.no_of_pieces
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
#		print(e)
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
#			print(e)
			return
		conn_id = 0x41727101980
		action = 0x0
		transaction_id = int(random.randrange(0, 255))
		conn_buf = struct.pack('!Qii', conn_id, action, transaction_id) 
		try:	
			#print('in try')	
			mysocket.sendto(conn_buf, (ip, port))
			#print('conn')
			response = mysocket.recvfrom(2048)
			#print("udp")
			resp_buf = response[0]
			#print(resp_buf)
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
#			print(e)
			sys.exit()

		except Exception as e:
 #           		print(e)
            		return

def getpeers(mytorrent):
	peers_list = []
	if mytorrent.tracker_list != None:
		for i in mytorrent.tracker_list:
		#	print(i)
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
#		print i
		if i[0][:4] == 'http':
			peers = connect_httptracker(mytorrent, tracker)
		elif i[0][:3] == 'udp':
			peers = connect_udptracker(mytorrent, tracker)
		peers_list = peers
	
	#print peers_list
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
	#print (binascii.hexlify(message))
	return message


def not_interested():
	message_id = 3
	length = 1
	message = struct.pack('!ib', length, message_id)
	return message


def unpack_unchoke(response):
#	print response[0:4]
	length = struct.unpack('!I',response[0:4])
	message_id = struct.unpack('!B',response[4:5])
#	print('ANKITA')
#	print length[0]
#	print message_id[0]
	return True

def unpack_data_hshake(message):
#	print (message)
#	print type(message)
	length = int(message[0:8], 16)
	#print length
	message_id = int(message[8:10], 16)
	#print 'DECODEEE'
#	print length, message_id
	if length == 5 and message_id == 4:
		return 'have', int(message[10:18], 16) 
	elif length == 1 and message_id == 1:
#		print 'unchoke'
		return 'unchoke', 0
	elif length == 1 and message_id == 0:
		return 'choke', 0
	else:
		return 'garbage', 0
	
def pack_request(piece_no, block_no, block):
	length = 13
	message_id = 6
	index = piece_no
	begin = block_no * block.block_size
	blength = block.block_size
#	print 'its length'
#	print blength
	message = struct.pack('!IBIII', length, message_id, index, begin, blength)
	return message


def handshake(mytorrent):
	pstr = b"BitTorrent protocol"
	pstrlen = chr(len(pstr))
	reserved = "\x00\x00\x00\x00\x00\x00\x00\x00"
	message = pstrlen + pstr + reserved + mytorrent.hash_info + mytorrent.peer_id
	return message

def bitfield (response, peer):
#	print "IN BITFIELD"
	peer.read_buffer = bitstring.BitArray(hex = binascii.hexlify(response)).bin
	peer.have_piece = True
#	print (peer.read_buffer)

def unpack_data_hshake(response, peer):
	#pstrlen = response[0:1]
	#print int(pstrlen)
	pstrlen = 19
	pstr = response[1 : pstrlen + 1]
	reserved = response[pstrlen + 1: pstrlen + 9]
	info_hash = response[pstrlen + 9: pstrlen + 29]
	peer_id = response[pstrlen + 29: pstrlen + 49]
#	print pstrlen, pstr, reserved, info_hash, peer_id
	peer.handshake = True
	return response[pstrlen + 49:]
def unpack_response(response, peer):
	global pieces_list
	#print type(response)
	l = response[0:4]
#	print len(l)
#	print type(l)
#	print l
#	print peer
	try:

		length = struct.unpack('!I',response[0:4])
		message_id = struct.unpack('!B',response[4:5])
		#print length[0], message_id[0]
		if length[0] == 1 and message_id[0] == 0:
			pass
		#	print ("choke")
		
		elif length[0] == 1 and message_id[0] == 1:
	#		print ("unchoke")
			peer.unchoke = True
		elif length[0] == 1 and message_id[0] == 2:
			pass
	#		print ("inteerested")
		elif length[0] == 1 and message_id[0] == 3:
			pass
	#		print ("not")
		elif length[0] == 5 and message_id[0] == 4:
			piece = struct.unpack('!I', response[5:9])
			#print piece
			peer.have_pieces.append(piece[0])
			peer.have_piece = True
			if len(response[9:]) != 0:
				unpack_response(response[9:], peer)

		elif message_id[0] == 5:
			pay_length = length[0] - 1
			bitfield(response[5:pay_length + 5], peer)
			if len(response[pay_length + 5:]) != 0:
				unpack_response(response[pay_length + 5:], peer)
		elif length[0] == 13 and message_id[0] == 6:
			pass
		else:
			unpack_response(response[1:], peer)
	except Exception as e:
		pass
#		print "main error"
#		print e
		
def handi(mytorrent, conn_peer_list):
	global pieces_list
	have_piece_peers = []
	handshake_message = handshake(mytorrent)
	for peer in conn_peer_list:
		try:
			peer.socket.send(handshake_message)
#			print(handshake_message)
		except:	
			pass	
#			print "hshake_senderrpr"
	for peer in conn_peer_list:
#		print peer.socket
		try:
			response = peer.socket.recv(2048)
			#print len(response)
			respond = unpack_data_hshake(response, peer)
			if len(respond) != 0: 
				unpack_response(respond, peer)
			
		except Exception as e:
			pass
	for peer in conn_peer_list:
		if peer.unchoke == False and peer.have_piece == True:
			interest_msage = pack_interested()
			try:
				peer.socket.send(interest_msage)
			except:
				pass
#				print "interested_senderror"
	for peer in conn_peer_list:
		if peer.unchoke == False and peer.have_piece == True:
			try:
				response = peer.socket.recv(2048)
				if len(response) != 0:
					unpack_response(response, peer)
			except:
				pass
#				print "interested_recverror"
	
	for peer in conn_peer_list:
		if peer.unchoke == True and peer.have_piece == True:
#			print "PEER"
			have_piece_peers.append(peer)
	
	for piece in pieces_list:
		for peer in have_piece_peers:
			try:
				if peer.read_buffer[piece.piece_no] == "1" or piece.piece_no in peer.have_pieces:
					piece.peers.append(peer)
			except Exception as e:
				pass
	return have_piece_peers, pieces_list		
def get_piece(i, piece):
	response_list = []
	global size
	global all_piece
	size = 0
	for block in range(piece.nos_of_blocks):
		b = piece.blocks_list[block]
		if b.downloading == False:
			b.downloading = True
			try:
				data = ""
				dataa = ""
				message = pack_request(piece.piece_no, block, piece.blocks_list[block])
				i.socket.send(message)
				time.sleep(5)
				response = i.socket.recv(16397)
				#time.sleep(2)
				length = struct.unpack("!I", response[0:4])
				idd = struct.unpack("!B", response[4:5])
				if idd[0] == 7:
					piecee = struct.unpack("!I", response[5:9])
					offset = struct.unpack("!I", response[9:13])
					block_no = int(offset[0] / BLOCK_SIZE)
					data = response[13:]
					if len(data) == BLOCK_SIZE:
						s = size + len(data)
						all_piece += 1
						size = s
						pbar.update(1)
						piece.blocks_list[block_no].data = data
					else: 
						b.downloading = False
				else :
					b.downloading = False
			except Exception as e:
			
				
				#print e
				
				pass

	return piece			

def get_data(peer, mytorrent):
	global pieces_list
	global all_piece
	global block_num
	while all_piece != block_num:
		for piece in pieces_list:
			if peer in piece.peers and piece.piece_downloaded == False:
				piece = get_piece(peer, piece)
		time.sleep(10)
							
	

def connect_peers(peers_list, mytorrent):
	global all_piece
	global pieces_list
	conn_peer_list = []
	have_piece_peers = []
	for i in range(mytorrent.no_of_pieces):
		piece = Piece(mytorrent, i)
		pieces_list.append(piece) 
	if peers_list != None:
		for i in peers_list:
			ip = i[0]
			port = i[1][-1]
			new_peer = Peer(mytorrent, ip, port)
			if new_peer.connected == True:
				conn_peer_list.append(new_peer)
	have_piece_peers, pieces_list = handi(mytorrent, conn_peer_list)
	pieces_list.sort(key = lambda c : c.nos_of_peers)
	if have_piece_peers != None:
		for i in have_piece_peers:
			thread = threading.Thread(target = get_data, args = [i, mytorrent])
			thread_list.append(thread)
			thread.start()
			if i > 10: 
				break
	if thread_list != None:
		for thread in thread_list:
			thread.join()

def writeinfile( f):
	global piece_list
	for piece in piece_list:
		for block in range(piece.nos_of_blocks):
			piece.data += piece.blocks_list[block_no].data 
			
		f.write(piece.data)
		
		
		
		
mytorrent = readtorrent()
try:
	filepath = os.path.join(sys.argv[2], mytorrent.name)
except:
	filepath = mytorrent.name
f = open(filepath, "w")
block_num = mytorrent.no_of_pieces * mytorrent.piece_size / BLOCK_SIZE
pbar = tqdm(total = block_num)
while all_piece != block_num:
	peers_list = getpeers(mytorrent)
	connect_peers(peers_list, mytorrent)

pbar.close()
writeinfile(f)
