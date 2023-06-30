import unittest
from t import Torrent

class TorrentTestCase(unittest.TestCase):
    def setUp(self):
        self.torrent = Torrent()

    def test_load_from_path(self):
        # Provide the path to an actual torrent file
        torrent_file_path = '/Users/username/Downloads/hap.torrent'

        # Call the load_from_path function
        self.torrent.load_from_path(torrent_file_path)

        # Assertions
        self.assertTrue(self.torrent.piece_length > 0)
        self.assertTrue(self.torrent.pieces)
        self.assertTrue(self.torrent.total_length > 0)
        self.assertTrue(self.torrent.info_hash)
        self.assertTrue(self.torrent.peer_id)
        self.assertTrue(self.torrent.announce_list)
        self.assertTrue(len(self.torrent.file_names) > 0)
        self.assertTrue(self.torrent.number_of_pieces > 0)

    def test_init_files(self):
        # Provide the path to an actual torrent file
        torrent_file_path = '/Users/username/Downloads/hap.torrent'

        # Call the load_from_path function
        self.torrent.load_from_path(torrent_file_path)

        # Call the init_files function
        self.torrent.init_files()

        # Assertions
        self.assertTrue(len(self.torrent.file_names) > 0)
        self.assertTrue(self.torrent.total_length > 0)

    def test_get_trackers(self):
        # Provide the path to an actual torrent file
        torrent_file_path = '/Users/username/Downloads/hap.torrent'

        # Call the load_from_path function
        self.torrent.load_from_path(torrent_file_path)

        # Call the get_trackers function
        trackers = self.torrent.get_trackers()

        # Assertions
        self.assertTrue(len(trackers) > 0)

    def test_generate_peer_id(self):
        # Call the generate_peer_id function
        peer_id = self.torrent.generate_peer_id()

        # Assertions
        self.assertTrue(peer_id)
        self.assertEqual(len(peer_id), 20)

if __name__ == '__main__':
    unittest.main()
