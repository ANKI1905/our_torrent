import bencoder #to bencode and decode file
import sys	#for command line args

class readtorrent:
	def __init__(self):
		self.tracker_list = ""
		self.piece_size = 0
		self.pieces = ""
		self.date = ""
		self.size = 0
		self.name = ""
		self.create = ""
		self.source = ""
		
	def getinfo(self, filename):
		fp = open(filename, "rb")
		data = fp.read()	#it is string
		decode_data = bencoder.decode(data)    #get a dictionary 
		if 'announce-list' in decode_data and 'info' in decode_data:
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




mytorrent = readtorrent()
mytorrent.getinfo(sys.argv[1])
print(mytorrent.tracker_list)
print(mytorrent.piece_size)
print(mytorrent.pieces)
print(mytorrent.date)
print(mytorrent.size)
print(mytorrent.name)
print(mytorrent.create)
print(mytorrent.source)


		
	
	
