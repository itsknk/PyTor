### PyTor
A Bit Torrent client implemented in python.


## To do
1. Parse the torrent flie. [Done]
2. Connect to the tracker.
3. Parse the tracker response.
4. Connect to peers and Handshake with peers.
5. Torrent Strategy.


## Code
1. Parsing Torrent Files
- The code segment encompasses the Torrent class, which encapsulates the necessary attributes and functions for loading and parsing torrent files, initializing file structures, retrieving trackers, and generating peer IDs.

- __init__(self): Initializes the attributes of the Torrent class, including variables to store the torrent file contents, total length of files, piece length, number of pieces, info hash, peer ID, announce list (trackers), file names, and number of pieces.

- load_from_path(self, path): Loads and parses a torrent file from the provided file path. It opens the file, decodes its contents, and extracts relevant information such as piece length, pieces, info hash, and announce list. It also generates a unique peer ID and initializes file structures. Finally, it calculates the number of pieces based on the total length and piece length, performs assertions for validation, and returns the Torrent object.

- init_files(self): Initializes the file names and calculates the total length of the torrent. This function handles both single-file and multi-file torrents. For multi-file torrents, it creates directories if they don't exist, constructs file paths, adds file names and lengths to the list, and sums up the lengths to calculate the total length. For single-file torrents, it simply adds the root name and length to the list. The function does not return a value.

- get_trackers(self): Retrieves the list of trackers from the torrent file. If the torrent file contains an announce-list field, it returns its value as the list of trackers. Otherwise, it returns a list containing the announce field value. This function returns a list of trackers.

- generate_peer_id(self): Generates a unique peer ID for the client. It uses the current timestamp as a seed, hashes it using SHA-1, and returns the generated peer ID as a string. This function returns a peer ID.


## License
[MIT](https://github.com/itsknk/PyTor/blob/master/LICENSE)