BITTORRENT CLIENT
1. Bittorrent is a CLI tool that downloads files from the BitTorrent network.
   It is build using python 2.7
2. This tool needs a lot of improvements, but it does its job, you can :
-	Read a torrent file.
-	Scrape udp or http trackers.
-	Connect to peers.
-	Ask them for the blocks you want.
-	Save a block in RAM, and when a piece is completed and checked, write the data into your hard drive.
-	It display the progress through progress bar continuously.

3. You can run the following command to install the dependencies using pip
	`pip install -r requirements.txt`
	
4. You first need to wait for the program to connect to some peers first, then it starts downloading.

5. Source :
-	[Kristen Widman's](http://www.kristenwidman.com/blog/how-to-write-a-bittorrent-client-part-1 "Kristen Widman's blog"). 
-	[Bittorrent Unofficial Spec](https://wiki.theory.org/BitTorrentSpecification "Bittorrent Unofficial Spec").

6. Input should be in the form of 
	python <Programm_name> <torrent_file_name> <Path_to_download> 
	
