import time

import select
from threading import Thread
from pubsub import pub
import rp
import logging
import m
import pe
import errno
import socket
import random


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
            piece = m.Piece(piece_index, block_offset, block_length, block).to_bytes()  # Create Piece message
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
            handshake = m.Handshake(self.torrent.info_hash)
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

    def _process_new_message(self, new_message: m.Message, peer: pe.Peer):
        """
        Process a new message received from a peer.

        Args:
            new_message: The new message object.
            peer: The peer object that sent the message.
        """
        if isinstance(new_message, m.Handshake) or isinstance(new_message, m.KeepAlive):
            logging.error("Handshake or KeepAlive should have already been handled")

        elif isinstance(new_message, m.Choke):
            peer.handle_choke()

        elif isinstance(new_message, m.UnChoke):
            peer.handle_unchoke()

        elif isinstance(new_message, m.Interested):
            peer.handle_interested()

        elif isinstance(new_message, m.NotInterested):
            peer.handle_not_interested()

        elif isinstance(new_message, m.Have):
            peer.handle_have(new_message)

        elif isinstance(new_message, m.BitField):
            peer.handle_bitfield(new_message)

        elif isinstance(new_message, m.Request):
            peer.handle_request(new_message)

        elif isinstance(new_message, m.Piece):
            peer.handle_piece(new_message)

        elif isinstance(new_message, m.Cancel):
            peer.handle_cancel()

        elif isinstance(new_message, m.Port):
            peer.handle_port_request()

        else:
            logging.error("Unknown message")
