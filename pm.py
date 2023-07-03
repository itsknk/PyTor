import p
import bitstring
import logging
from pubsub import pub


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
                pieces.append(p.Piece(i, piece_length, self.torrent.pieces[start:end]))
            else:
                pieces.append(p.Piece(i, self.torrent.piece_length, self.torrent.pieces[start:end]))

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
