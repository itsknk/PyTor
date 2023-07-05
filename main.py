import hashlib
import random
import socket
import sys
import struct
import math
import time
import os
import logging
import bitstring
import errno
import select
import ipaddress
import requests
import rp

from pubsub import pub
from struct import pack, unpack
from threading import Thread
from bcoding import bencode, bdecode
from urllib.parse import urlparse
from b import Block, BLOCK_SIZE, State



'''
PARSING TORRENT
'''													



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



'''
MESSAGE
'''



# String identifier of the protocol for BitTorrent V1
HANDSHAKE_PSTR_V1 = b"BitTorrent protocol"
HANDSHAKE_PSTR_LEN = len(HANDSHAKE_PSTR_V1)
LENGTH_PREFIX = 4


class WrongMessageException(Exception):
    """
    Custom exception class to indicate an error with the message.
    """
    pass

class Message:
    """
    Base class for BitTorrent messages.
    """

    def to_bytes(self):
        """
        Convert the message object to bytes.
        This method needs to be implemented by subclasses.
        """
        raise NotImplementedError()

    @classmethod
    def from_bytes(cls, payload):
        """
        Create a message object from bytes.
        This method needs to be implemented by subclasses.
        """
        raise NotImplementedError()

"""
UDP Tracker
"""

class UdpTrackerConnection(Message):
    """
    Represents a connection message for the UDP tracker.
    """

    def __init__(self):
        super(UdpTrackerConnection, self).__init__()
        self.conn_id = pack('>Q', 0x41727101980)  # Initialize connection ID to a specific value
        self.action = pack('>I', 0)  # Initialize action to 0 (connect)
        self.trans_id = pack('>I', random.randint(0, 100000))  # Generate a random transaction ID

    def to_bytes(self):
        """
        Convert the connection message to bytes.
        """
        return self.conn_id + self.action + self.trans_id

    def from_bytes(self, payload):
        """
        Create a connection message object from bytes.
        """
        self.action, = unpack('>I', payload[:4])  # Extract the action from the payload (first 4 bytes)
        self.trans_id, = unpack('>I', payload[4:8])  # Extract the transaction ID from the payload (next 4 bytes)
        self.conn_id, = unpack('>Q', payload[8:])  # Extract the connection ID from the payload (remaining bytes)


class UdpTrackerAnnounce(Message):
    """
    Represents an announce message for the UDP tracker.
    """

    def __init__(self, info_hash, conn_id, peer_id):
        super(UdpTrackerAnnounce, self).__init__()
        self.peer_id = peer_id  # Set the peer ID
        self.conn_id = conn_id  # Set the connection ID
        self.info_hash = info_hash  # Set the info hash
        self.trans_id = pack('>I', random.randint(0, 100000))  # Generate a random transaction ID
        self.action = pack('>I', 1)  # Set the action to 1 (announce)

    def to_bytes(self):
        """
        Convert the announce message to bytes.
        """
        conn_id = pack('>Q', self.conn_id)  # Convert the connection ID to bytes
        action = self.action  # Get the action
        trans_id = self.trans_id  # Get the transaction ID
        downloaded = pack('>Q', 0)  # Set downloaded to 0
        left = pack('>Q', 0)  # Set left to 0
        uploaded = pack('>Q', 0)  # Set uploaded to 0
        event = pack('>I', 0)  # Set event to 0
        ip = pack('>I', 0)  # Set IP address to 0
        key = pack('>I', 0)  # Set key to 0
        num_want = pack('>i', -1)  # Set num_want to -1 (default value)
        port = pack('>H', 0)  # Set port to 0

        return (conn_id + action + trans_id + self.info_hash + self.peer_id + downloaded +
                left + uploaded + event + ip + key + num_want + port)

    def from_bytes(self, payload):
        """
        Create an announce message object from bytes.
        """
        self.action, = unpack('>I', payload[:4])  # Extract the action from the payload (first 4 bytes)
        self.trans_id, = unpack('>I', payload[4:8])  # Extract the transaction ID from the payload (next 4 bytes)


class UdpTrackerAnnounceOutput:
    """
    Represents the output of the announce message for the UDP tracker.
    """

    def __init__(self):
        self.action = None  # Action field of the announce output
        self.trans_id = None  # Transaction ID field of the announce output
        self.interval = None  # Interval field of the announce output
        self.leechers = None  # Number of leechers field of the announce output
        self.seeders = None  # Number of seeders field of the announce output
        self.socket_addresses = []  # List to store socket addresses of peers 

    def from_bytes(self, payload):
        self.action, = unpack('>I', payload[:4])
        self.transaction_id, = unpack('>I', payload[4:8])
        self.interval, = unpack('>I', payload[8:12])
        self.leechers, = unpack('>I', payload[12:16])
        self.seeders, = unpack('>I', payload[16:20])
        self.list_sock_addr = self._parse_sock_addr(payload[20:])

    def _parse_sock_addr(self, raw_bytes):
        socks_addr = []

        # socket address : <IP(4 bytes)><Port(2 bytes)>
        # len(socket addr) == 6 bytes
        for i in range(int(len(raw_bytes) / 6)):
            start = i * 6
            end = start + 6
            ip = socket.inet_ntoa(raw_bytes[start:(end - 2)])
            raw_port = raw_bytes[(end - 2):end]
            port = raw_port[1] + raw_port[0] * 256

            socks_addr.append((ip, port))

        return socks_addr        

"""
Handshake message
"""

class Handshake(Message):
    """
    Represents the handshake message used in the BitTorrent protocol.
    """

    payload_length = 68
    total_length = payload_length

    def __init__(self, info_hash, peer_id=b'-ZZ0007-000000000000'):
        super(Handshake, self).__init__()

        assert len(info_hash) == 20
        assert len(peer_id) < 255
        self.peer_id = peer_id
        self.info_hash = info_hash

    def to_bytes(self):
        reserved = b'\x00' * 8
        handshake = pack(">B{}s8s20s20s".format(HANDSHAKE_PSTR_LEN),
                         HANDSHAKE_PSTR_LEN,
                         HANDSHAKE_PSTR_V1,
                         reserved,
                         self.info_hash,
                         self.peer_id)

        return handshake

    @classmethod
    def from_bytes(cls, payload):
        pstrlen, = unpack(">B", payload[:1])
        pstr, reserved, info_hash, peer_id = unpack(">{}s8s20s20s".format(pstrlen), payload[1:cls.total_length])

        if pstr != HANDSHAKE_PSTR_V1:
            raise ValueError("Invalid string identifier of the protocol")

        return Handshake(info_hash, peer_id)    

"""
Regular messages
"""

class KeepAlive(Message):
    """
        KEEP_ALIVE = <length>
            - payload length = 0 (4 bytes)
    """
    payload_length = 0
    total_length = 4

    def __init__(self):
        super(KeepAlive, self).__init__()

    def to_bytes(self):
        return pack(">I", self.payload_length)

    @classmethod
    def from_bytes(cls, payload):
        payload_length = unpack(">I", payload[:cls.total_length])

        if payload_length != 0:
            raise WrongMessageException("Not a Keep Alive message")

        return KeepAlive()        


class Choke(Message):
    """
        CHOKE = <length><message_id>
            - payload length = 1 (4 bytes)
            - message id = 0 (1 byte)
    """
    message_id = 0
    chokes_me = True

    payload_length = 1
    total_length = 5

    def __init__(self):
        super(Choke, self).__init__()

    def to_bytes(self):
        return pack(">IB", self.payload_length, self.message_id)

    @classmethod
    def from_bytes(cls, payload):
        payload_length, message_id = unpack(">IB", payload[:cls.total_length])
        if message_id != cls.message_id:
            raise WrongMessageException("Not a Choke message")

        return Choke()


class UnChoke(Message):
    """
        UnChoke = <length><message_id>
            - payload length = 1 (4 bytes)
            - message id = 1 (1 byte)
    """
    message_id = 1
    chokes_me = False

    payload_length = 1
    total_length = 5

    def __init__(self):
        super(UnChoke, self).__init__()

    def to_bytes(self):
        return pack(">IB", self.payload_length, self.message_id)

    @classmethod
    def from_bytes(cls, payload):
        payload_length, message_id = unpack(">IB", payload[:cls.total_length])

        if message_id != cls.message_id:
            raise WrongMessageException("Not an UnChoke message")

        return UnChoke()


class Interested(Message):
    """
        INTERESTED = <length><message_id>
            - payload length = 1 (4 bytes)
            - message id = 2 (1 byte)
    """
    message_id = 2
    interested = True

    payload_length = 1
    total_length = 4 + payload_length

    def __init__(self):
        super(Interested, self).__init__()

    def to_bytes(self):
        return pack(">IB", self.payload_length, self.message_id)

    @classmethod
    def from_bytes(cls, payload):
        payload_length, message_id = unpack(">IB", payload[:cls.total_length])

        if message_id != cls.message_id:
            raise WrongMessageException("Not an Interested message")

        return Interested()


class NotInterested(Message):
    """
        NOT INTERESTED = <length><message_id>
            - payload length = 1 (4 bytes)
            - message id = 3 (1 byte)
    """
    message_id = 3
    interested = False

    payload_length = 1
    total_length = 5

    def __init__(self):
        super(NotInterested, self).__init__()

    def to_bytes(self):
        return pack(">IB", self.payload_length, self.message_id)

    @classmethod
    def from_bytes(cls, payload):
        payload_length, message_id = unpack(">IB", payload[:cls.total_length])
        if message_id != cls.message_id:
            raise WrongMessageException("Not a Non Interested message")

        return Interested()


class Have(Message):
    """
        HAVE = <length><message_id><piece_index>
            - payload length = 5 (4 bytes)
            - message_id = 4 (1 byte)
            - piece_index = zero based index of the piece (4 bytes)
    """
    message_id = 4

    payload_length = 5
    total_length = 4 + payload_length

    def __init__(self, piece_index):
        super(Have, self).__init__()
        self.piece_index = piece_index

    def to_bytes(self):
        pack(">IBI", self.payload_length, self.message_id, self.piece_index)

    @classmethod
    def from_bytes(cls, payload):
        payload_length, message_id, piece_index = unpack(">IBI", payload[:cls.total_length])
        if message_id != cls.message_id:
            raise WrongMessageException("Not a Have message")

        return Have(piece_index)


class BitField(Message):
    """
        BITFIELD = <length><message id><bitfield>
            - payload length = 1 + bitfield_size (4 bytes)
            - message id = 5 (1 byte)
            - bitfield = bitfield representing downloaded pieces (bitfield_size bytes)
    """
    message_id = 5

    # Unknown until given a bitfield
    payload_length = -1
    total_length = -1

    def __init__(self, bitfield):  # bitfield is a bitstring.BitArray
        super(BitField, self).__init__()
        self.bitfield = bitfield
        self.bitfield_as_bytes = bitfield.tobytes()
        self.bitfield_length = len(self.bitfield_as_bytes)

        self.payload_length = 1 + self.bitfield_length
        self.total_length = 4 + self.payload_length

    def to_bytes(self):
        return pack(">IB{}s".format(self.bitfield_length),
                    self.payload_length,
                    self.message_id,
                    self.bitfield_as_bytes)

    @classmethod
    def from_bytes(cls, payload):
        payload_length, message_id = unpack(">IB", payload[:5])
        bitfield_length = payload_length - 1

        if message_id != cls.message_id:
            raise WrongMessageException("Not a BitField message")

        raw_bitfield, = unpack(">{}s".format(bitfield_length), payload[5:5 + bitfield_length])
        bitfield = bitstring.BitArray(bytes=bytes(raw_bitfield))

        return BitField(bitfield)


class Request(Message):
    """
        REQUEST = <length><message id><piece index><block offset><block length>
            - payload length = 13 (4 bytes)
            - message id = 6 (1 byte)
            - piece index = zero based piece index (4 bytes)
            - block offset = zero based of the requested block (4 bytes)
            - block length = length of the requested block (4 bytes)
    """
    message_id = 6

    payload_length = 13
    total_length = 4 + payload_length

    def __init__(self, piece_index, block_offset, block_length):
        super(Request, self).__init__()

        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block_length = block_length

    def to_bytes(self):
        return pack(">IBIII",
                    self.payload_length,
                    self.message_id,
                    self.piece_index,
                    self.block_offset,
                    self.block_length)

    @classmethod
    def from_bytes(cls, payload):
        payload_length, message_id, piece_index, block_offset, block_length = unpack(">IBIII",
                                                                                     payload[:cls.total_length])
        if message_id != cls.message_id:
            raise WrongMessageException("Not a Request message")

        return Request(piece_index, block_offset, block_length)


class PPiece(Message):
    """
        PIECE = <length><message id><piece index><block offset><block>
        - length = 9 + block length (4 bytes)
        - message id = 7 (1 byte)
        - piece index =  zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block = block as a bytestring or bytearray (block_length bytes)
    """
    message_id = 7

    payload_length = -1
    total_length = -1

    def __init__(self, block_length, piece_index, block_offset, block):
        super(PPiece, self).__init__()

        self.block_length = block_length
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block = block

        self.payload_length = 9 + block_length
        self.total_length = 4 + self.payload_length

    def to_bytes(self):
        return pack(">IBII{}s".format(self.block_length),
                    self.payload_length,
                    self.message_id,
                    self.piece_index,
                    self.block_offset,
                    self.block)

    @classmethod
    def from_bytes(cls, payload):
        block_length = len(payload) - 13
        payload_length, message_id, piece_index, block_offset, block = unpack(">IBII{}s".format(block_length),
                                                                              payload[:13 + block_length])
        if message_id != cls.message_id:
            raise WrongMessageException("Not a Piece message")

        return PPiece(block_length, piece_index, block_offset, block)


class Cancel(Message):
    """CANCEL = <length><message id><piece index><block offset><block length>
        - length = 13 (4 bytes)
        - message id = 8 (1 byte)
        - piece index = zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block length = length of the requested block (4 bytes)"""
    message_id = 8

    payload_length = 13
    total_length = 4 + payload_length

    def __init__(self, piece_index, block_offset, block_length):
        super(Cancel, self).__init__()

        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block_length = block_length

    def to_bytes(self):
        return pack(">IBIII",
                    self.payload_length,
                    self.message_id,
                    self.piece_index,
                    self.block_offset,
                    self.block_length)

    @classmethod
    def from_bytes(cls, payload):
        payload_length, message_id, piece_index, block_offset, block_length = unpack(">IBIII",
                                                                                     payload[:cls.total_length])
        if message_id != cls.message_id:
            raise WrongMessageException("Not a Cancel message")

        return Cancel(piece_index, block_offset, block_length)


class Port(Message):
    """
        PORT = <length><message id><port number>
            - length = 5 (4 bytes)
            - message id = 9 (1 byte)
            - port number = listen_port (4 bytes)
    """
    message_id = 9

    payload_length = 5
    total_length = 4 + payload_length

    def __init__(self, listen_port):
        super(Port, self).__init__()

        self.listen_port = listen_port

    def to_bytes(self):
        return pack(">IBI",
                    self.payload_length,
                    self.message_id,
                    self.listen_port)

    @classmethod
    def from_bytes(cls, payload):
        payload_length, message_id, listen_port = unpack(">IBI", payload[:cls.total_length])

        if message_id != cls.message_id:
            raise WrongMessageException("Not a Port message")

        return Port(listen_port)


class MessageDispatcher:

    def __init__(self, payload):
        self.payload = payload

    def dispatch(self):
        try:
            payload_length, message_id, = unpack(">IB", self.payload[:5])
        except Exception as e:
            logging.warning("Error when unpacking message : %s" % e.__str__())
            return None

        map_id_to_message = {
            0: Choke,
            1: UnChoke,
            2: Interested,
            3: NotInterested,
            4: Have,
            5: BitField,
            6: Request,
            7: PPiece,
            8: Cancel,
            9: Port
        }

        if message_id not in list(map_id_to_message.keys()):
            raise WrongMessageException("Wrong message id")
        return map_id_to_message[message_id].from_bytes(self.payload)        



'''
PIECES
'''



class Piece(object):
    def __init__(self, piece_index: int, piece_size: int, piece_hash: str):
        """
        Initializes a Piece object with the specified piece index, size, and hash.

        Args:
            piece_index (int): The index of the piece.
            piece_size (int): The size of the piece.
            piece_hash (str): The expected hash of the piece's data.
        """
        self.piece_index: int = piece_index
        self.piece_size: int = piece_size
        self.piece_hash: str = piece_hash
        self.is_full: bool = False
        self.files = []
        self.raw_data: bytes = b''
        self.number_of_blocks: int = int(math.ceil(float(piece_size) / BLOCK_SIZE))
        self.blocks: list[Block] = []

        self._init_blocks()

    def update_block_status(self):
        """
        Updates the status of the blocks in the piece.
        If a block is pending for too long, it sets the block to free.
        """
        for i, block in enumerate(self.blocks):
            if block.state == State.PENDING and (time.time() - block.last_seen) > 5:
                self.blocks[i] = Block()

    def set_block(self, offset, data):
        """
        Sets the data for a specific block within the piece based on the offset.

        Args:
            offset (int): The offset within the piece where the block starts.
            data (bytes): The data to set for the block.
        """
        index = int(offset / BLOCK_SIZE)

        if not self.is_full and not self.blocks[index].state == State.FULL:
            self.blocks[index].data = data
            self.blocks[index].state = State.FULL

    def get_block(self, block_offset, block_length):
        """
        Retrieves a specific block of data from the piece based on the block's offset and length.

        Args:
            block_offset (int): The offset of the block within the piece.
            block_length (int): The length of the block.

        Returns:
            bytes: The retrieved block of data.
        """
        return self.raw_data[block_offset:block_length]

    def get_empty_block(self):
        """
        Finds and returns an empty block within the piece.
        If all blocks are full or the piece is already full, it returns None.

        Returns:
            tuple or None: A tuple containing the piece index, block offset, and block size of the empty block,
                           or None if no empty block is found.
        """
        if self.is_full:
            return None

        for block_index, block in enumerate(self.blocks):
            if block.state == State.FREE:
                self.blocks[block_index].state = State.PENDING
                self.blocks[block_index].last_seen = time.time()
                return self.piece_index, block_index * BLOCK_SIZE, block.block_size

        return None

    def are_all_blocks_full(self):
        """
        Checks if all blocks of the piece are full.

        Returns:
            bool: True if all blocks are full, False otherwise.
        """
        for block in self.blocks:
            if block.state == State.FREE or block.state == State.PENDING:
                return False

        return True

    def set_to_full(self):
        """
        Sets the piece to full if all blocks are filled and the data passes the validation check.
        Writes the completed piece to disk and publishes a message indicating the completion.

        Returns:
            bool: True if the piece is successfully set to full, False otherwise.
        """
        data = self._merge_blocks()

        if not self._valid_blocks(data):
            self._init_blocks()
            return False

        self.is_full = True
        self.raw_data = data
        self._write_piece_on_disk()
        pub.sendMessage('PiecesManager.PieceCompleted', piece_index=self.piece_index)

        return True

    def _init_blocks(self):
        """
        Initializes the blocks of the piece based on the number of blocks required.
        """
        self.blocks = []

        if self.number_of_blocks > 1:
            for i in range(self.number_of_blocks):
                self.blocks.append(Block())

            # Last block of last piece, the special block
            if (self.piece_size % BLOCK_SIZE) > 0:
                self.blocks[self.number_of_blocks - 1].block_size = self.piece_size % BLOCK_SIZE

        else:
            self.blocks.append(Block(block_size=int(self.piece_size)))

    def _write_piece_on_disk(self):
        """
        Writes the completed piece's data to the corresponding files on disk.
        """
        for file in self.files:
            path_file = file["path"]
            file_offset = file["fileOffset"]
            piece_offset = file["pieceOffset"]
            length = file["length"]

            try:
                f = open(path_file, 'r+b')  # Already existing file
            except IOError:
                f = open(path_file, 'wb')  # New file
            except Exception:
                logging.exception("Can't write to file")
                return

            f.seek(file_offset)
            f.write(self.raw_data[piece_offset:piece_offset + length])
            f.close()

    def _merge_blocks(self):
        """
        Merges the data of all blocks into a single byte string.
        """
        buf = b''

        for block in self.blocks:
            buf += block.data

        return buf

    def _valid_blocks(self, piece_raw_data):
        """
        Validates the piece's raw data by comparing its hash with the expected hash.
        """
        hashed_piece_raw_data = hashlib.sha1(piece_raw_data).digest()

        if hashed_piece_raw_data == self.piece_hash:
            return True

        logging.warning("Error Piece Hash")
        logging.debug("{} : {}".format(hashed_piece_raw_data, self.piece_hash))
        return False



'''
MANAGING PIECES
'''



class PiecesManager(object):
    def __init__(self, torrent):
        """
        Initializes a PiecesManager object with the specified torrent.

        Args:
            torrent: The torrent object.
        """
        self.torrent = torrent
        self.number_of_pieces = int(torrent.number_of_pieces)
        self.bitfield = bitstring.BitArray(self.number_of_pieces)
        self.pieces = self._generate_pieces()
        self.files = self._load_files()
        self.complete_pieces = 0

        for file in self.files:
            id_piece = file['idPiece']
            self.pieces[id_piece].files.append(file)

        # events
        pub.subscribe(self.receive_block_piece, 'PiecesManager.Piece')
        pub.subscribe(self.update_bitfield, 'PiecesManager.PieceCompleted')

    def update_bitfield(self, piece_index):
        """
        Updates the bitfield to indicate the completion of a piece.

        Args:
            piece_index (int): The index of the completed piece.
        """
        self.bitfield[piece_index] = 1

    def receive_block_piece(self, piece):
        """
        Receives a block of data for a piece and updates the piece's blocks accordingly.
        If all blocks of a piece are filled, sets the piece to full.

        Args:
            piece (tuple): A tuple containing the piece index, piece offset, and piece data.
        """
        piece_index, piece_offset, piece_data = piece

        if self.pieces[piece_index].is_full:
            return

        self.pieces[piece_index].set_block(piece_offset, piece_data)

        if self.pieces[piece_index].are_all_blocks_full():
            if self.pieces[piece_index].set_to_full():
                self.complete_pieces += 1

    def get_block(self, piece_index, block_offset, block_length):
        """
        Retrieves a specific block of data from a piece.

        Args:
            piece_index (int): The index of the piece.
            block_offset (int): The offset of the block within the piece.
            block_length (int): The length of the block.

        Returns:
            bytes: The retrieved block of data.
        """
        for piece in self.pieces:
            if piece_index == piece.piece_index:
                if piece.is_full:
                    return piece.get_block(block_offset, block_length)
                else:
                    break

        return None

    def all_pieces_completed(self):
        """
        Checks if all pieces have been completed.

        Returns:
            bool: True if all pieces are completed, False otherwise.
        """
        for piece in self.pieces:
            if not piece.is_full:
                return False

        return True

    def _generate_pieces(self):
        """
        Generates the pieces based on the torrent information.

        Returns:
            list: A list of Piece objects representing the pieces of the torrent.
        """
        pieces = []
        last_piece = self.number_of_pieces - 1

        for i in range(self.number_of_pieces):
            start = i * 20
            end = start + 20

            if i == last_piece:
                piece_length = self.torrent.total_length - (self.number_of_pieces - 1) * self.torrent.piece_length
                pieces.append(Piece(i, piece_length, self.torrent.pieces[start:end]))
            else:
                pieces.append(Piece(i, self.torrent.piece_length, self.torrent.pieces[start:end]))

        return pieces

    def _load_files(self):
        """
        Loads the files of the torrent and assigns them to the corresponding pieces.

        Returns:
            list: A list of file objects with their metadata and piece assignments.
        """
        files = []
        piece_offset = 0
        piece_size_used = 0

        for f in self.torrent.file_names:
            current_size_file = f["length"]
            file_offset = 0

            while current_size_file > 0:
                id_piece = int(piece_offset / self.torrent.piece_length)
                piece_size = self.pieces[id_piece].piece_size - piece_size_used

                if current_size_file - piece_size < 0:
                    file = {"length": current_size_file,
                            "idPiece": id_piece,
                            "fileOffset": file_offset,
                            "pieceOffset": piece_size_used,
                            "path": f["path"]
                            }
                    piece_offset += current_size_file
                    file_offset += current_size_file
                    piece_size_used += current_size_file
                    current_size_file = 0

                else:
                    current_size_file -= piece_size
                    file = {"length": piece_size,
                            "idPiece": id_piece,
                            "fileOffset": file_offset,
                            "pieceOffset": piece_size_used,
                            "path": f["path"]
                            }
                    piece_offset += piece_size
                    file_offset += piece_size
                    piece_size_used = 0

                files.append(file)
        return files



'''
PEERS
'''



class Peer(object):
    def __init__(self, number_of_pieces, ip, port=6881):
        # Initialize the Peer object with its attributes
        self.last_call = 0.0
        self.has_handshaked = False
        self.healthy = False
        self.read_buffer = b''  # Buffer to store received data
        self.socket = None  # Socket object for communication
        self.ip = ip  # IP address of the peer
        self.port = port  # Port number of the peer
        self.number_of_pieces = number_of_pieces  # Total number of pieces in the torrent
        self.bit_field = bitstring.BitArray(number_of_pieces)  # Bit field representing the pieces
        self.state = {
            'am_choking': True,
            'am_interested': False,
            'peer_choking': True,
            'peer_interested': False,
        }
        # Initial state of the peer, including choking and interest flags

    def __hash__(self):
        return "%s:%d" % (self.ip, self.port)
        # Returns a unique hash for the Peer object based on its IP address and port

    def connect(self):
        try:
            self.socket = socket.create_connection((self.ip, self.port), timeout=2)
            self.socket.setblocking(False)
            logging.debug("Connected to peer ip: {} - port: {}".format(self.ip, self.port))
            self.healthy = True
            # Attempt to create a socket connection with the peer and set it to non-blocking mode
            # Set the 'healthy' flag to True if connection is successful

        except Exception as e:
            print("Failed to connect to peer (ip: %s - port: %s - %s)" % (self.ip, self.port, e.__str__()))
            return False
            # If connection fails, print an error message and return False

        return True
        # Return True if the connection is successfully established

    def send_to_peer(self, msg):
        try:
            self.socket.send(msg)
            self.last_call = time.time()
            # Send the provided message to the peer over the socket connection
            # Update the last_call attribute with the current time

        except Exception as e:
            self.healthy = False
            logging.error("Failed to send to peer : %s" % e.__str__())
            # If sending fails, set the 'healthy' flag to False and log an error message

    def is_eligible(self):
        now = time.time()
        return (now - self.last_call) > 0.2
        # Check if the time elapsed since the last call is greater than 0.2 seconds
        # Return True if eligible, False otherwise

    def has_piece(self, index):
        return self.bit_field[index]
        # Check if the peer has the piece at the given index in its bit field
        # Return True if the peer has the piece, False otherwise

    def am_choking(self):
        return self.state['am_choking']
        # Check if the peer is choking (not sending data to the client)
        # Return True if the peer is choking, False otherwise

    def am_unchoking(self):
        return not self.am_choking()
        # Check if the peer is unchoking (sending data to the client)
        # Return True if the peer is unchoking, False otherwise

    def is_choking(self):
        return self.state['peer_choking']
        # Check if the peer is being choked by the client (client not sending requests)
        # Return True if the peer is being choked, False otherwise

    def is_unchoked(self):
        return not self.is_choking()
        # Check if the peer is unchoked by the client (client sending requests)
        # Return True if the peer is unchoked, False otherwise

    def is_interested(self):
        return self.state['peer_interested']
        # Check if the peer is interested in the client's pieces
        # Return True if the peer is interested, False otherwise

    def am_interested(self):
        return self.state['am_interested']
        # Check if the client is interested in the peer's pieces
        # Return True if the client is interested, False otherwise

    def handle_choke(self):
        logging.debug('handle_choke - %s' % self.ip)
        self.state['peer_choking'] = True
        # Handle the choke message from the peer
        # Set the 'peer_choking' flag to True

    def handle_unchoke(self):
        logging.debug('handle_unchoke - %s' % self.ip)
        self.state['peer_choking'] = False
        # Handle the unchoke message from the peer
        # Set the 'peer_choking' flag to False

    def handle_interested(self):
        logging.debug('handle_interested - %s' % self.ip)
        self.state['peer_interested'] = True
        # Handle the interested message from the peer
        # Set the 'peer_interested' flag to True

        if self.am_choking():
            unchoke = UnChoke().to_bytes()
            self.send_to_peer(unchoke)
            # If the client is choking, send an unchoke message to the peer

    def handle_not_interested(self):
        logging.debug('handle_not_interested - %s' % self.ip)
        self.state['peer_interested'] = False
        # Handle the not interested message from the peer
        # Set the 'peer_interested' flag to False

    def handle_have(self, have):
        """
        :type have: message.Have
        """
        logging.debug('handle_have - ip: %s - piece: %s' % (self.ip, have.piece_index))
        self.bit_field[have.piece_index] = True
        # Handle the have message from the peer
        # Set the bit at the piece index in the bit field to True

        if self.is_choking() and not self.state['am_interested']:
            interested = Interested().to_bytes()
            self.send_to_peer(interested)
            self.state['am_interested'] = True
            # If the client is choking and not interested, send an interested message to the peer
            # Set the 'am_interested' flag to True

    def handle_bitfield(self, bitfield):
        """
        :type bitfield: message.BitField
        """
        logging.debug('handle_bitfield - %s - %s' % (self.ip, bitfield.bitfield))
        self.bit_field = bitfield.bitfield
        # Handle the bitfield message from the peer
        # Update the bit field of the peer with the received bit field

        if self.is_choking() and not self.state['am_interested']:
            interested = Interested().to_bytes()
            self.send_to_peer(interested)
            self.state['am_interested'] = True
            # If the client is choking and not interested, send an interested message to the peer
            # Set the 'am_interested' flag to True

    def handle_request(self, request):
        """
        :type request: message.Request
        """
        logging.debug('handle_request - %s' % self.ip)
        if self.is_interested() and self.is_unchoked():
            pub.sendMessage('PiecesManager.PeerRequestsPiece', request=request, peer=self)
            # Handle the request message from the peer
            # If the client is interested and unchoked, publish the message for the PiecesManager to handle

    def handle_piece(self, message):
        """
        :type message: message.Piece
        """
        pub.sendMessage('PiecesManager.Piece', piece=(message.piece_index, message.block_offset, message.block))
        # Handle the piece message from the peer
        # Publish the message for the PiecesManager to handle

    def handle_cancel(self):
        logging.debug('handle_cancel - %s' % self.ip)
        # Handle the cancel message from the peer

    def handle_port_request(self):
        logging.debug('handle_port_request - %s' % self.ip)
        # Handle the port request message from the peer

    def _handle_handshake(self):
        try:
            handshake_message = Handshake.from_bytes(self.read_buffer)
            self.has_handshaked = True
            self.read_buffer = self.read_buffer[handshake_message.total_length:]
            logging.debug('handle_handshake - %s' % self.ip)
            return True
            # Handle the handshake message from the peer
            # Set the 'has_handshaked' flag to True and update the read buffer

        except Exception:
            logging.exception("First message should always be a handshake message")
            self.healthy = False
            # If an exception occurs while handling the handshake message, set the 'healthy' flag to False

        return False
        # Return False if the handshake message handling fails

    def _handle_keep_alive(self):
        # Handle the keep-alive message from the peer
        try:
            keep_alive = KeepAlive.from_bytes(self.read_buffer)
            logging.debug('handle_keep_alive - %s' % self.ip)
        except WrongMessageException:
            return False
        except Exception:
            logging.exception("Error KeepALive, (need at least 4 bytes : {})".format(len(self.read_buffer)))
            return False
        # Update the read buffer and return True if keep-alive message handling is successful    
        self.read_buffer = self.read_buffer[keep_alive.total_length:]
        return True                

    def get_messages(self):
        # Continuously loop while there is data in the read buffer and the peer is healthy
        # Handle handshake and keep-alive messages and continue to the next iteration if successful
        while len(self.read_buffer) > 4 and self.healthy:
            if (not self.has_handshaked and self._handle_handshake()) or self._handle_keep_alive():
                continue

            payload_length, = struct.unpack(">I", self.read_buffer[:4])
            total_length = payload_length + 4

            if len(self.read_buffer) < total_length:
                break
            else:
                # Extract the payload from the read buffer based on the payload length
                payload = self.read_buffer[:total_length]
                self.read_buffer = self.read_buffer[total_length:]

            try:
                # Dispatch the received message using the MessageDispatcher class
                # If a valid message is received, yield it for further processing
                received_message = MessageDispatcher(payload).dispatch()
                if received_message:
                    yield received_message
            except WrongMessageException as e:
                # If an exception occurs while dispatching the message, set the 'healthy' flag to False and break the loop
                logging.exception(e.__str__())  



'''
MANAGING PEERS
'''



class PeersManager(Thread):
    def __init__(self, torrent, pieces_manager):
        Thread.__init__(self)
        self.peers = []  # List to store peer objects
        self.torrent = torrent  # Torrent object
        self.pieces_manager = pieces_manager  # PiecesManager object
        self.rarest_pieces = rp.RarestPieces(pieces_manager)  # RarestPieces object
        self.pieces_by_peer = [[0, []] for _ in range(pieces_manager.number_of_pieces)]  # List to store pieces by peer
        self.is_active = True  # Flag to control the thread execution

        # Events
        pub.subscribe(self.peer_requests_piece, 'PeersManager.PeerRequestsPiece')  # Subscribe to 'PeerRequestsPiece' event
        pub.subscribe(self.peers_bitfield, 'PeersManager.updatePeersBitfield')  # Subscribe to 'updatePeersBitfield' event

    def peer_requests_piece(self, request=None, peer=None):
        """
        Process a piece request from a peer.

        Args:
            request: The piece request.
            peer: The peer object that sent the request.
        """
        if not request or not peer:
            logging.error("empty request/peer message")

        piece_index, block_offset, block_length = request.piece_index, request.block_offset, request.block_length

        block = self.pieces_manager.get_block(piece_index, block_offset, block_length)  # Get the requested block
        if block:
            piece = Piece(piece_index, block_offset, block_length, block).to_bytes()  # Create Piece message
            peer.send_to_peer(piece)  # Send the Piece message to the peer
            logging.info("Sent piece index {} to peer: {}".format(request.piece_index, peer.ip))

    def peers_bitfield(self, bitfield=None):
        """
        Update the peer's bitfield in the pieces_by_peer list.

        Args:
            bitfield: The bitfield of a peer.
        """
        for i in range(len(self.pieces_by_peer)):
            if bitfield[i] == 1 and peer not in self.pieces_by_peer[i][1] and self.pieces_by_peer[i][0]:
                self.pieces_by_peer[i][1].append(peer)
                self.pieces_by_peer[i][0] = len(self.pieces_by_peer[i][1])

    def get_random_peer_having_piece(self, index):
        """
        Get a random peer that has a specific piece.

        Args:
            index: The index of the desired piece.

        Returns:
            A random peer object that has the specified piece, or None if no such peer is found.
        """
        ready_peers = []

        for peer in self.peers:
            if peer.is_eligible() and peer.is_unchoked() and peer.am_interested() and peer.has_piece(index):
                ready_peers.append(peer)

        return random.choice(ready_peers) if ready_peers else None

    def has_unchoked_peers(self):
        """
        Check if there are any unchoked peers.

        Returns:
            True if there are unchoked peers, False otherwise.
        """
        for peer in self.peers:
            if peer.is_unchoked():
                return True
        return False

    def unchoked_peers_count(self):
        """
        Get the count of unchoked peers.

        Returns:
            The count of unchoked peers.
        """
        cpt = 0
        for peer in self.peers:
            if peer.is_unchoked():
                cpt += 1
        return cpt

    @staticmethod
    def _read_from_socket(sock):
        """
        Read data from a socket.

        Args:
            sock: The socket to read from.

        Returns:
            The read data.
        """
        data = b''

        while True:
            try:
                buff = sock.recv(4096)
                if len(buff) <= 0:
                    break

                data += buff
            except socket.error as e:
                err = e.args[0]
                if err != errno.EAGAIN or err != errno.EWOULDBLOCK:
                    logging.debug("Wrong errno {}".format(err))
                break
            except Exception:
                logging.exception("Recv failed")
                break

        return data

    def run(self):
        while self.is_active:
            read = [peer.socket for peer in self.peers] # Get a list of sockets to read from
            read_list, _, _ = select.select(read, [], [], 1) # Wait for available data to read

            for socket in read_list:
                peer = self.get_peer_by_socket(socket)
                if not peer.healthy:
                    self.remove_peer(peer)
                    continue

                try:
                    payload = self._read_from_socket(socket) # Read data from the socket
                except Exception as e:
                    logging.error("Recv failed %s" % e.__str__())
                    self.remove_peer(peer)
                    continue

                peer.read_buffer += payload

                for message in peer.get_messages():
                    self._process_new_message(message, peer) # Process the received message               

    def _do_handshake(self, peer):
        """
        Perform the handshake with a peer.

        Args:
            peer: The peer object to perform the handshake with.

        Returns:
            True if the handshake is successful, False otherwise.
        """
        try:
            handshake = Handshake(self.torrent.info_hash)
            peer.send_to_peer(handshake.to_bytes())
            logging.info("new peer added : %s" % peer.ip)
            return True

        except Exception:
            logging.exception("Error when sending Handshake message")

        return False

    def add_peers(self, peers):
        """
        Add new peers to the peers list.

        Args:
            peers: A list of peer objects to add.
        """
        for peer in peers:
            if self._do_handshake(peer):
                self.peers.append(peer)
            else:
                print("Error _do_handshake")

    def remove_peer(self, peer):
        """
        Remove a peer from the peers list.

        Args:
            peer: The peer object to remove.
        """
        if peer in self.peers:
            try:
                peer.socket.close()
            except Exception:
                logging.exception("")

            self.peers.remove(peer)

    def get_peer_by_socket(self, socket):
        """
        Get a peer object based on the associated socket.

        Args:
            socket: The socket associated with the peer.

        Returns:
            The peer object.

        Raises:
            Exception: If the peer is not present in the peers list.
        """
        for peer in self.peers:
            if socket == peer.socket:
                return peer

        raise Exception("Peer not present in peer_list")

    def _process_new_message(self, new_message: Message, peer: Peer):
        """
        Process a new message received from a peer.

        Args:
            new_message: The new message object.
            peer: The peer object that sent the message.
        """
        if isinstance(new_message, Handshake) or isinstance(new_message, KeepAlive):
            logging.error("Handshake or KeepAlive should have already been handled")

        elif isinstance(new_message, Choke):
            peer.handle_choke()

        elif isinstance(new_message, UnChoke):
            peer.handle_unchoke()

        elif isinstance(new_message, Interested):
            peer.handle_interested()

        elif isinstance(new_message, NotInterested):
            peer.handle_not_interested()

        elif isinstance(new_message, Have):
            peer.handle_have(new_message)

        elif isinstance(new_message, BitField):
            peer.handle_bitfield(new_message)

        elif isinstance(new_message, Request):
            peer.handle_request(new_message)

        elif isinstance(new_message, PPiece):
            peer.handle_piece(new_message)

        elif isinstance(new_message, Cancel):
            peer.handle_cancel()

        elif isinstance(new_message, Port):
            peer.handle_port_request()

        else:
            logging.error("Unknown message")



'''
TRACKER
'''



# Constants to control the number of peer connections.
MAX_PEERS_TRY_CONNECT = 30  # Maximum number of attempted connections to peers from trackers.
MAX_PEERS_CONNECTED = 8     # Maximum number of successfully connected peers.

# Class to represent a socket address (IP and port).
class SockAddr:
    def __init__(self, ip, port, allowed=True):
        self.ip = ip        # IP address of the socket.
        self.port = port    # Port number of the socket.
        self.allowed = allowed  # A flag to indicate if this socket is allowed.

    def __hash__(self):
        return "%s:%d" % (self.ip, self.port)

# The Tracker class handles tracker communication and peer connections.
class Tracker(object):
    def __init__(self, torrent):
        self.torrent = torrent  # Torrent object containing information about the torrent file.
        self.threads_list = []  # List to store threads for peer connections (not used in the provided code).
        self.connected_peers = {}  # Dictionary to store connected peers with their hash as the key.
        self.dict_sock_addr = {}   # Dictionary to store socket addresses of potential peers.

    # Get peers from all trackers associated with the torrent.
    def get_peers_from_trackers(self):
        for i, tracker in enumerate(self.torrent.announce_list):
            if len(self.dict_sock_addr) >= MAX_PEERS_TRY_CONNECT:
                break  # Stop trying to connect to more peers if the maximum limit is reached.

            tracker_url = tracker[0]  # Extract the tracker URL from the announce list.

            if str.startswith(tracker_url, "http"):
                try:
                    self.http_scraper(self.torrent, tracker_url)  # Scrape peers from HTTP tracker.
                except Exception as e:
                    logging.error("HTTP scraping failed: %s " % e.__str__())

            elif str.startswith(tracker_url, "udp"):
                try:
                    self.udp_scrapper(tracker_url)  # Scrape peers from UDP tracker.
                except Exception as e:
                    logging.error("UDP scraping failed: %s " % e.__str__())

            else:
                logging.error("unknown scheme for: %s " % tracker_url)

        self.try_peer_connect()  # Attempt to connect to the discovered peers.

        return self.connected_peers  # Return the connected peers dictionary.

    # Try to establish connections to the discovered peers.
    def try_peer_connect(self):
        logging.info("Trying to connect to %d peer(s)" % len(self.dict_sock_addr))

        for _, sock_addr in self.dict_sock_addr.items():
            if len(self.connected_peers) >= MAX_PEERS_CONNECTED:
                break  # Stop trying to connect more peers if the maximum limit is reached.

            # Create a new Peer object to represent the peer to be connected.
            new_peer = Peer(int(self.torrent.number_of_pieces), sock_addr.ip, sock_addr.port)

            if not new_peer.connect():
                continue  # If connection fails, skip to the next potential peer.

            print('Connected to %d/%d peers' % (len(self.connected_peers), MAX_PEERS_CONNECTED))

            self.connected_peers[new_peer.__hash__()] = new_peer  # Add the connected peer to the dictionary.

    # Scrape peers from an HTTP tracker.
    def http_scraper(self, torrent, tracker):
        params = {
            'info_hash': torrent.info_hash,
            'peer_id': torrent.peer_id,
            'uploaded': 0,
            'downloaded': 0,
            'port': 6881,
            'left': torrent.total_length,
            'event': 'started'
        }

        try:
            answer_tracker = requests.get(tracker, params=params, timeout=5)  # Send GET request to the tracker.
            list_peers = bdecode(answer_tracker.content)  # Decode the response using bencoding.

            offset = 0
            if not type(list_peers['peers']) == list:
                '''
                    - Handles bytes form of list of peers
                    - IP address in bytes form:
                        - Size of each IP: 6 bytes
                        - The first 4 bytes are for IP address
                        - Next 2 bytes are for port number
                    - To unpack initial 4 bytes !i (big-endian, 4 bytes) is used.
                    - To unpack next 2 bytes !H(big-endian, 2 bytes) is used.
                '''
                for _ in range(len(list_peers['peers'])//6):
                    ip = struct.unpack_from("!i", list_peers['peers'], offset)[0]
                    ip = socket.inet_ntoa(struct.pack("!i", ip))
                    offset += 4
                    port = struct.unpack_from("!H", list_peers['peers'], offset)[0]
                    offset += 2
                    s = SockAddr(ip, port)
                    self.dict_sock_addr[s.__hash__()] = s
            else:
                for p in list_peers['peers']:
                    s = SockAddr(p['ip'], p['port'])
                    self.dict_sock_addr[s.__hash__()] = s

        except Exception as e:
            logging.exception("HTTP scraping failed: %s" % e.__str__())

    # Scrape peers from a UDP tracker.
    def udp_scrapper(self, announce):
        torrent = self.torrent
        parsed = urlparse(announce)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(4)
        ip, port = socket.gethostbyname(parsed.hostname), parsed.port

        if ipaddress.ip_address(ip).is_private:
            return  # Skip private IP addresses.

        tracker_connection_input = UdpTrackerConnection()
        response = self.send_message((ip, port), sock, tracker_connection_input)  # Send connection request to tracker.

        if not response:
            raise Exception("No response for UdpTrackerConnection")

        tracker_connection_output = UdpTrackerConnection()
        tracker_connection_output.from_bytes(response)  # Parse the response from the tracker.

        tracker_announce_input = UdpTrackerAnnounce(torrent.info_hash, tracker_connection_output.conn_id,
                                                    torrent.peer_id)
        response = self.send_message((ip, port), sock, tracker_announce_input)  # Send announce request to tracker.

        if not response:
            raise Exception("No response for UdpTrackerAnnounce")

        tracker_announce_output = UdpTrackerAnnounceOutput()
        tracker_announce_output.from_bytes(response)  # Parse the response from the tracker.

        for ip, port in tracker_announce_output.list_sock_addr:
            sock_addr = SockAddr(ip, port)

            if sock_addr.__hash__() not in self.dict_sock_addr:
                self.dict_sock_addr[sock_addr.__hash__()] = sock_addr

        print("Got %d peers" % len(self.dict_sock_addr))

    # Send a message to the tracker and receive the response.
    def send_message(self, conn, sock, tracker_message):
        message = tracker_message.to_bytes()
        trans_id = tracker_message.trans_id
        action = tracker_message.action
        size = len(message)

        sock.sendto(message, conn)  # Send the message to the tracker.

        try:
            response = PeersManager._read_from_socket(sock)  # Read the response from the socket.
        except socket.timeout as e:
            logging.debug("Timeout : %s" % e)
            return
        except Exception as e:
            logging.exception("Unexpected error when sending message : %s" % e.__str__())
            return

        if len(response) < size:
            logging.debug("Did not get full message.")

        if action != response[0:4] or trans_id != response[4:8]:
            logging.debug("Transaction or Action ID did not match")

        return response



'''
MAIN
'''



class Run(object):
    percentage_completed = -1
    last_log_line = ""

    def __init__(self):
        try:
            torrent_file = sys.argv[1]  # Get the torrent file path from command-line arguments.
        except IndexError:
            logging.error("No torrent file provided!")
            sys.exit(0)

        self.torrent = Torrent().load_from_path(torrent_file)  # Load the torrent file.
        self.tracker = Tracker(self.torrent)  # Create a tracker object for the torrent.

        # Create objects for managing pieces and peers.
        self.pieces_manager = PiecesManager(self.torrent)
        self.peers_manager = PeersManager(self.torrent, self.pieces_manager)

        # Start the PeersManager and PiecesManager.
        self.peers_manager.start()
        logging.info("PeersManager Started")
        logging.info("PiecesManager Started")

    def start(self):
        peers_dict = self.tracker.get_peers_from_trackers()  # Get peers from the tracker.
        self.peers_manager.add_peers(peers_dict.values())  # Add the fetched peers to the PeersManager.

        # Continue downloading until all pieces are completed.
        while not self.pieces_manager.all_pieces_completed():
            if not self.peers_manager.has_unchoked_peers():  # If there are no unchoked peers, wait for 1 second.
                time.sleep(1)
                logging.info("No unchoked peers")
                continue

            # Loop through pieces and download them from available peers.
            for piece in self.pieces_manager.pieces:
                index = piece.piece_index

                if self.pieces_manager.pieces[index].is_full:
                    continue

                peer = self.peers_manager.get_random_peer_having_piece(index)  # Get a random peer that has the piece.
                if not peer:
                    continue

                self.pieces_manager.pieces[index].update_block_status()  # Update the status of blocks in the piece.

                data = self.pieces_manager.pieces[index].get_empty_block()  # Get an empty block in the piece.
                if not data:
                    continue

                # Create a Request message to request the block from the peer.
                piece_index, block_offset, block_length = data
                piece_data = Request(piece_index, block_offset, block_length).to_bytes()
                peer.send_to_peer(piece_data)  # Send the Request message to the peer.

            self.display_progression()  # Display the download progression.

            time.sleep(0.1)  # Sleep for a short time.

        logging.info("File(s) downloaded successfully.")
        self.display_progression()  # Display the final download progression.

        self._exit_threads()  # Exit the download threads.

    def display_progression(self):
        new_progression = 0

        # Calculate the total downloaded data to calculate download percentage.
        for i in range(self.pieces_manager.number_of_pieces):
            for j in range(self.pieces_manager.pieces[i].number_of_blocks):
                if self.pieces_manager.pieces[i].blocks[j].state == State.FULL:
                    new_progression += len(self.pieces_manager.pieces[i].blocks[j].data)

        if new_progression == self.percentage_completed:
            return

        number_of_peers = self.peers_manager.unchoked_peers_count()  # Get the number of unchoked peers.
        percentage_completed = float((float(new_progression) / self.torrent.total_length) * 100)

        current_log_line = "Connected peers: {} - {}% completed | {}/{} pieces".format(number_of_peers,
                                                                                         round(percentage_completed, 2),
                                                                                         self.pieces_manager.complete_pieces,
                                                                                         self.pieces_manager.number_of_pieces)
        if current_log_line != self.last_log_line:
            print(current_log_line)

        self.last_log_line = current_log_line
        self.percentage_completed = new_progression

    def _exit_threads(self):
        self.peers_manager.is_active = False  # Set the PeersManager's is_active flag to False.
        os._exit(0)  # Exit the program.

# Entry point of the program.
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)  # Set the logging level to DEBUG.

    run = Run()
    run.start()        
