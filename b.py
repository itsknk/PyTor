from enum import Enum

# Define the block size as 2^14, which is 16 KB
BLOCK_SIZE = 2 ** 14


# Define an enumeration for the possible states of a block
class State(Enum):
    FREE = 0  # The block is free and available
    PENDING = 1  # The block is pending, waiting to be filled
    FULL = 2  # The block is full, containing data


class Block:
    def __init__(self, state: State = State.FREE, block_size: int = BLOCK_SIZE, data: bytes = b'', last_seen: float = 0):
        """
        Initializes a Block object with the specified parameters.

        Args:
            state (State): The state of the block (default: State.FREE).
            block_size (int): The size of the block in bytes (default: BLOCK_SIZE).
            data (bytes): The data contained in the block (default: b'').
            last_seen (float): The timestamp when the block was last seen (default: 0).
        """
        self.state: State = state
        self.block_size: int = block_size
        self.data: bytes = data
        self.last_seen: float = last_seen

    def __str__(self):
        """
        Returns a string representation of the Block object.

        Returns:
            str: The string representation of the Block object.
        """
        return "%s - %d - %d - %d" % (self.state, self.block_size, len(self.data), self.last_seen)
