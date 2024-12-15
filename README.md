# BitTorrent Client

## Overview
This project involves building a BitTorrent client capable of downloading publicly available files using the BitTorrent protocol. The client will implement various stages of the protocol, from decoding .torrent files to downloading and assembling the complete file.

---

## Features
1. **Decode Bencoded Strings**
   - Understand and decode strings encoded in the bencoding format.

2. **Parse Torrent File**
   - Read and extract metadata from a .torrent file, including:
     - Tracker URLs
     - File information
     - Piece hashes

3. **Calculate Info Hash**
   - Compute the SHA-1 hash of the `info` dictionary from the .torrent file for peer identification.

4. **Piece Hashes**
   - Validate downloaded pieces using the hash provided in the .torrent file.

5. **Discover Peers**
   - Connect to the tracker and retrieve a list of peers available for file sharing.

6. **Peer Handshake**
   - Implement the BitTorrent handshake protocol to establish communication with peers.

7. **Download a Piece**
    - Download individual pieces of the file from peers and validate them.

8. **Download the Whole File**
    - Assemble all pieces to reconstruct the original file.