import hashlib
import math
import time
import logging

from pubsub import pub
from b import Block, BLOCK_SIZE, State


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
