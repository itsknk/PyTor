import math
from bcoding import bencode, bdecode
import logging
import hashlib
import time
import os

class Torrent(object):
    def __init__(self):
        # Initialize the attributes of the Torrent class
        self.torrent_file = {}  # Stores the contents of the torrent file
        self.total_length: int = 0  # Total length of all files in the torrent
        self.piece_length: int = 0  # Length of each piece in the torrent
        self.pieces: int = 0  # Number of pieces in the torrent
        self.info_hash: str = ''  # Hash value of the 'info' dictionary in the torrent
        self.peer_id: str = ''  # Unique identifier for the client (peer)
        self.announce_list = ''  # List of trackers for the torrent
        self.file_names = []  # List of file names in the torrent
        self.number_of_pieces: int = 0  # Number of pieces calculated based on total length and piece length

    def load_from_path(self, path):
        """
        Load and parse a torrent file from the given path.

        Args:
            path (str): Path to the torrent file.

        Returns:
            Torrent: The Torrent object itself.

        Raises:
            AssertionError: If the total length or file names are not valid.
        """

        # Open the torrent file and decode its contents
        with open(path, 'rb') as file:
            contents = bdecode(file)

        # Store the parsed contents in the Torrent object
        self.torrent_file = contents
        self.piece_length = self.torrent_file['info']['piece length']
        self.pieces = self.torrent_file['info']['pieces']

        # Calculate the info hash of the 'info' dictionary and store it
        raw_info_hash = bencode(self.torrent_file['info'])
        self.info_hash = hashlib.sha1(raw_info_hash).digest()

        # Generate a unique peer ID for the client
        self.peer_id = self.generate_peer_id()

        # Retrieve the list of trackers from the torrent file
        self.announce_list = self.get_trackers()

        # Initialize the file names and calculate the total length of the torrent
        self.init_files()

        # Calculate the number of pieces based on the total length and piece length
        self.number_of_pieces = math.ceil(self.total_length / self.piece_length)

        # Log the announce list and file names for debugging purposes
        logging.debug(self.announce_list)
        logging.debug(self.file_names)

        # Validate that the total length and file names are valid
        assert self.total_length > 0, "Invalid total length"
        assert len(self.file_names) > 0, "No file names found"

        return self

    def init_files(self):
        """
        Initialize the file names and calculate the total length of the torrent.

        This function handles both single-file and multi-file torrents.

        For single-file torrents, the root name is used as the file name.
        For multi-file torrents, the file names are constructed using the 'name' and 'path' fields.

        For both cases, the total length of the torrent is calculated by summing the lengths of all files.

        Returns:
            None
        """

        # Get the root name of the torrent
        root = self.torrent_file['info']['name']

        if 'files' in self.torrent_file['info']:
            # Handle multi-file torrents
            if not os.path.exists(root):
                os.mkdir(root, 0o0766)

            for file in self.torrent_file['info']['files']:
                # Construct the path for each file
                path_file = os.path.join(root, *file["path"])

                # Create directories if they don't exist
                if not os.path.exists(os.path.dirname(path_file)):
                    os.makedirs(os.path.dirname(path_file))

                # Add the file name and length to the list
                self.file_names.append({"path": path_file, "length": file["length"]})

                # Sum the lengths to calculate the total length
                self.total_length += file["length"]

        else:
            # Handle single-file torrents
            self.file_names.append({"path": root, "length": self.torrent_file['info']['length']})
            self.total_length = self.torrent_file['info']['length']

    def get_trackers(self):
        """
        Retrieve the list of trackers from the torrent file.

        If the 'announce-list' field is present, return its value.
        Otherwise, return a list containing the 'announce' field value.

        Returns:
            list: List of trackers.
        """

        if 'announce-list' in self.torrent_file:
            return self.torrent_file['announce-list']
        else:
            return [[self.torrent_file['announce']]]

    def generate_peer_id(self):
        """
        Generate a unique peer ID for the client.

        The peer ID is calculated by hashing the current timestamp.

        Returns:
            str: Generated peer ID.
        """

        seed = str(time.time())
        return hashlib.sha1(seed.encode('utf-8')).digest()
