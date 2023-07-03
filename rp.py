import logging

class RarestPieces(object):
    def __init__(self, pieces_manager):
        """
        Initialize the RarestPieces object.

        Args:
            pieces_manager: An object representing the pieces manager in the BitTorrent client.
        """
        self.pieces_manager = pieces_manager
        self.rarest_pieces = []

        # Initialize the rarest pieces list with placeholders for each piece
        for piece_number in range(self.pieces_manager.number_of_pieces):
            self.rarest_pieces.append({"idPiece": piece_number, "numberOfPeers": 0, "peers": []})

    def peers_bitfield(self, bitfield=None, peer=None, piece_index=None):
        """
        Update the rarest pieces based on the peers' bitfields and piece completions.

        Args:
            bitfield: A list representing the bitfield of a peer.
            peer: The peer object for which the bitfield is being updated.
            piece_index: The index of a completed piece (optional).

        Raises:
            Exception: If there are no more rarest pieces.
        """
        if len(self.rarest_pieces) == 0:
            raise Exception("No more piece")

        # Check if a piece has been completed
        if piece_index is not None:
            try:
                del self.rarest_pieces[piece_index]
            except Exception:
                logging.exception("Failed to remove rarest piece")

        # Update the peer's bitfield
        else:
            for i in range(len(self.rarest_pieces)):
                if bitfield[i] == 1 and peer not in self.rarest_pieces[i]["peers"]:
                    self.rarest_pieces[i]["peers"].append(peer)
                    self.rarest_pieces[i]["numberOfPeers"] = len(self.rarest_pieces[i]["peers"])

    def get_sorted_pieces(self):
        """
        Get the rarest pieces sorted by the number of peers.

        Returns:
            A list of rarest pieces sorted by the number of peers.
        """
        return sorted(self.rarest_pieces, key=lambda x: x['numberOfPeers'])
