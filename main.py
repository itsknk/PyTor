import sys
from b import State

import time
import pem
import pm
import t
import tr
import logging
import os
import m

class Run(object):
    percentage_completed = -1
    last_log_line = ""

    def __init__(self):
        try:
            torrent_file = sys.argv[1]  # Get the torrent file path from command-line arguments.
        except IndexError:
            logging.error("No torrent file provided!")
            sys.exit(0)

        self.torrent = t.Torrent().load_from_path(torrent_file)  # Load the torrent file.
        self.tracker = tr.Tracker(self.torrent)  # Create a tracker object for the torrent.

        # Create objects for managing pieces and peers.
        self.pieces_manager = pm.PiecesManager(self.torrent)
        self.peers_manager = pem.PeersManager(self.torrent, self.pieces_manager)

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
                piece_data = m.Request(piece_index, block_offset, block_length).to_bytes()
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
