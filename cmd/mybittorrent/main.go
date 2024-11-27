package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unsafe"

	bencode "github.com/jackpal/bencode-go"
	"golang.org/x/sync/errgroup"
)

func main() {
	switch cmd := os.Args[1]; cmd {
	case "decode":
		input := os.Args[2]
		val, tail, err := decodeBencode(input)
		if err != nil {
			fmt.Printf("%s: %s", tail, err)
			return
		}
		if tail != "" {
			fmt.Printf("didn't consume the whole input: tail %q", tail)
			return
		}

		out, _ := json.Marshal(val)
		fmt.Println(string(out))
	case "info":
		filePath := os.Args[2]
		f, err := os.Open(filePath)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		var t Tracker
		err = bencode.Unmarshal(f, &t)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Tracker URL: %s\n", t.Announce)
		fmt.Printf("Length: %d\n", t.Info.Length)

		infoHash, err := t.InfoHash()
		if err != nil {
			panic(err)
		}

		fmt.Printf("Info Hash: %x\n", infoHash)
		fmt.Printf("Piece Length: %d\n", t.Info.PieceLength)

		fmt.Printf("Piece Hashes:\n")
		piecesIter := t.Info.PiecesAll()
		piecesIter(func(_ int, piece []byte) bool {
			fmt.Printf("%x\n", piece)
			return true
		})
	case "peers":
		filePath := os.Args[2]
		f, err := os.Open(filePath)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		var t Tracker
		err = bencode.Unmarshal(f, &t)
		if err != nil {
			panic(err)
		}

		peers, err := discoverPeers(t)
		if err != nil {
			panic(err)
		}

		for _, peer := range peers {
			fmt.Println(peer.String())
		}
	case "handshake":
		filePath := os.Args[2]
		peer := os.Args[3]

		f, err := os.Open(filePath)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		var t Tracker
		err = bencode.Unmarshal(f, &t)
		if err != nil {
			panic(err)
		}

		conn, err := net.Dial("tcp", peer)
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		infoHash, err := t.InfoHash()
		if err != nil {
			panic(err)
		}

		hsk := newHandshake(infoHash)

		_, err = hsk.WriteTo(conn)
		if err != nil {
			panic(err)
		}

		_, err = hsk.ReadFrom(conn)
		if err != nil {
			panic(err)
		}

		if hsk.Tag != 19 {
			panic("unexpected handshake response")
		}

		fmt.Printf("Peer ID: %x\n", hsk.PeerID)
	case "download_piece":
		err := downloadPieceCmd(os.Args[2:])
		if err != nil {
			fmt.Println("Download piece command failed: " + err.Error())
			os.Exit(1)
		}
	case "download":
		err := downloadCmd(os.Args[2:])
		if err != nil {
			fmt.Println("Download command failed: " + err.Error())
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command: " + cmd)
		os.Exit(1)
	}
}

type Peer struct {
	conn io.ReadWriter

	mu  sync.Mutex
	msg message
}

func NewPeer(conn io.ReadWriter) *Peer {
	p := &Peer{
		conn: conn,
	}
	p.msg.payload = p.msg.buf[:]
	return p
}

func (p *Peer) Handshake(infoHash []byte) ([]byte, error) {
	hsk := newHandshake(infoHash)

	_, err := hsk.WriteTo(p.conn)
	if err != nil {
		return nil, err
	}

	_, err = hsk.ReadFrom(p.conn)
	if err != nil {
		return nil, err
	}

	if hsk.Tag != protocolStrLen {
		return nil, fmt.Errorf("handshake: unexpected tag %v", hsk.Tag)
	}

	return hsk.PeerID[:], nil
}

func (p *Peer) Recv(typ MessageType) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		_, err := p.msg.ReadFrom(p.conn)
		if err == io.EOF {
			continue
		}
		if err != nil {
			return nil, err
		}
		if p.msg.typ != typ {
			return nil, fmt.Errorf("recv: expected type %v, got %v", typ, p.msg.typ)
		}
		return p.msg.payload, nil
	}
}

func (p *Peer) Send(typ MessageType, m MessagePayload) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	msg := p.msg
	msg.typ = typ

	var n int
	if m != nil {
		var err error
		n, err = m.Read(msg.payload[:maxPayloadSize])
		if err != nil {
			return err
		}
	}
	msg.length = uint32(1 + n)

	_, err := msg.WriteTo(p.conn)
	return err
}

type MessageType uint8

const (
	Choke         MessageType = 0
	Unchoke       MessageType = 1
	Interested    MessageType = 2
	NotInterested MessageType = 3
	Have          MessageType = 4
	Bitfield      MessageType = 5
	Request       MessageType = 6
	Piece         MessageType = 7
	Cancel        MessageType = 8
)

const (
	maxBlockSize   = 1 << 14
	maxPayloadSize = maxBlockSize + 8 + 8
)

type MessagePayload interface {
	io.Reader
}

type ZeroPayload struct{}

func (p ZeroPayload) Read(b []byte) (int, error) {
	return 0, nil
}

type RawPayload []byte

func (p RawPayload) Read(b []byte) (int, error) {
	if len(b) < len([]byte(p)) {
		return 0, io.ErrShortBuffer
	}
	n := copy(b, []byte(p))
	return n, nil
}

type RequestPayload struct {
	Piece uint32
	Begin uint32
	BLen  uint32
}

func (p RequestPayload) Read(b []byte) (int, error) {
	if len(b) < 3*4 {
		return 0, io.ErrShortBuffer
	}
	packUint32(b, p.Piece, p.Begin, p.BLen)
	return 3 * 4, nil
}

func packUint32(buf []byte, v ...uint32) {
	for n, val := range v {
		binary.BigEndian.PutUint32(buf[n*4:], val)
	}
}

type message struct {
	length  uint32
	typ     MessageType
	payload []byte
	buf     [maxPayloadSize]byte
}

func (m *message) WriteTo(w io.Writer) (int64, error) {
	var buf [5]byte
	binary.BigEndian.PutUint32(buf[:], m.length)
	buf[4] = byte(m.typ)

	_, err := w.Write(buf[:])
	if err != nil {
		return 0, err
	}

	// fast exit if m doesn't have payload
	if m.length == 1 {
		return 5, nil
	}

	n, err := w.Write(m.payload[:m.length-1])
	if err != nil {
		return 0, err
	}
	return int64(5 + n), nil
}

func (m *message) ReadFrom(r io.Reader) (int64, error) {
	var buf [5]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, err
	}
	m.length = binary.BigEndian.Uint32(buf[:])
	m.typ = MessageType(buf[4])

	m.payload = m.buf[:m.length-1]
	n, err := io.ReadFull(r, m.payload)
	if err != nil {
		return 0, err
	}
	return int64(len(buf) + n), nil
}

const protocolStrLen = 19

type handshake struct {
	// Tag is the length of the protocol string, always 19
	Tag byte
	// Proto is the protocol string "BitTorrent protocol"
	Proto [protocolStrLen]byte
	// Reserved is reserved bytes, which are all set to zero
	Reserved [8]byte
	// InfoHash is the info hash of the torrent
	InfoHash [20]byte
	// PeerID is the id of the peer
	PeerID [20]byte
}

func newHandshake(infoHash []byte) handshake {
	return handshake{
		Tag:      protocolStrLen,
		Proto:    [protocolStrLen]byte([]byte("BitTorrent protocol")),
		InfoHash: [20]byte(infoHash),
		// hard-coded for test implementation
		PeerID: [20]byte([]byte("00112233445566778899")),
	}
}

func (m handshake) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.BigEndian, m)
	if err != nil {
		return 0, err
	}
	return int64(unsafe.Sizeof(m)), nil
}

func (m *handshake) ReadFrom(r io.Reader) (int64, error) {
	err := binary.Read(r, binary.BigEndian, m)
	if err != nil {
		return 0, err
	}
	return int64(unsafe.Sizeof(m)), nil
}
func decodeBencode(str string) (interface{}, string, error) {
	tag := str[0]
	switch {
	case unicode.IsDigit(rune(tag)):
		head, tail, ok := strings.Cut(str, ":")
		if !ok {
			return nil, "", fmt.Errorf("can't find colon in %q", str)
		}

		slen, err := strconv.Atoi(head)
		if err != nil {
			return "", "", err
		}
		return tail[:slen], tail[slen:], nil
	case tag == 'i':
		head, tail, ok := strings.Cut(str[1:], "e")
		if !ok {
			return nil, "", fmt.Errorf("can't find end of %q", str)
		}
		n, err := strconv.Atoi(head)
		return n, tail, err
	case tag == 'l':
		var list []interface{}
		str = str[1:]
		for {
			var (
				v   interface{}
				err error
			)
			v, str, err = decodeBencode(str)
			if err != nil {
				return nil, str, err
			}
			list = append(list, v)
			// consume the end of the list and exit
			if str[0] == 'e' {
				str = str[1:]
				break
			}
		}
		return list, str, nil
	case tag == 'd':
		dict := make(map[string]interface{}, 0)
		str = str[1:]
		for {
			var (
				v   interface{}
				err error
			)
			v, str, err = decodeBencode(str)
			if err != nil {
				return nil, str, err
			}
			k, ok := v.(string)
			if !ok {
				return nil, str, fmt.Errorf("key must be string, got %T (%v)", v, v)
			}
			v, str, err = decodeBencode(str)
			if err != nil {
				return nil, str, err
			}
			dict[k] = v
			// consume the end of the list and exit
			if str[0] == 'e' {
				str = str[1:]
				break
			}
		}
		return dict, str, nil
	default:
		return "", str, errors.ErrUnsupported
	}
}

func downloadPieceCmd(args []string) error {
	flags := flag.NewFlagSet("download_piece", flag.ExitOnError)

	var outPath string
	flags.StringVar(&outPath, "o", "", "Ouput path")

	if err := flags.Parse(args); err != nil {
		return err
	}

	filePath := flags.Arg(0)
	piece, _ := strconv.Atoi(flags.Arg(1))

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	var t Tracker
	err = bencode.Unmarshal(f, &t)
	if err != nil {
		return err
	}

	peers, err := discoverPeers(t)
	if err != nil {
		return err
	}

	conn, err := net.Dial("tcp", peers[0].String())
	if err != nil {
		return err
	}
	defer conn.Close()

	peer := NewPeer(conn)

	err = handshakePeer(t, peer)
	if err != nil {
		return err
	}

	if payload, err := peer.Recv(Bitfield); err != nil {
		return nil
	} else {
		// TODO: check that bitfield's payload has the len(pieces) bits set
		fmt.Printf("bitfield - %d\n", payload)
	}

	if err := peer.Send(Interested, nil); err != nil {
		return nil
	}

	if payload, err := peer.Recv(Unchoke); err != nil {
		return nil
	} else {
		fmt.Printf("unchoke - %d\n", payload)
	}

	pf, err := os.CreateTemp("", filePath)
	if err != nil {
		return err
	}
	defer pf.Close()

	_, err = downloadPiece(peer, t, piece, pf)
	if err != nil {
		return err
	}

	pf.Seek(0, io.SeekStart)

	h := sha1.New()
	if _, err := io.Copy(h, pf); err != nil {
		return err
	}

	fmt.Printf("Piece hash: %x\n", h.Sum(nil))

	if err := os.Rename(pf.Name(), outPath); err != nil {
		os.Remove(pf.Name())
		return err
	}

	fmt.Printf("Piece %d downloaded to %s.\n", piece, outPath)

	return nil
}

func downloadCmd(args []string) error {
	flags := flag.NewFlagSet("download_piece", flag.ExitOnError)

	var outPath string
	// Default the output path to current directory if not provided
	flags.StringVar(&outPath, "o", "./", "Output path")

	if err := flags.Parse(args); err != nil {
		return err
	}

	// Check that the torrent file is provided as the first argument
	torrentFile := flags.Arg(0)
	if torrentFile == "" {
		return fmt.Errorf("torrent file is required")
	}

	// Parse the tracker from the torrent file
	t, err := newTrackerFromPath(torrentFile)
	if err != nil {
		return err
	}

	// Discover peers from the tracker
	peersAddr, err := discoverPeers(t)
	if err != nil {
		return err
	}

	// Retrieve the info hash of the torrent
	infoHash, err := t.InfoHash()
	if err != nil {
		return err
	}

	// Prepare a slice to hold peer connections
	peers := make([]*Peer, len(peersAddr))
	for i, addr := range peersAddr {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			return err
		}
		defer conn.Close()

		peer := NewPeer(conn)

		// Perform the handshake with the peer
		peerID, err := peer.Handshake(infoHash)
		if err != nil {
			return err
		}

		// Receive the bitfield payload from the peer
		if payload, err := peer.Recv(Bitfield); err != nil {
			return err
		} else {
			fmt.Printf("peer %x (%s): bitfield - %d\n", peerID, addr, payload)
		}

		// Send interested message to the peer
		if err := peer.Send(Interested, nil); err != nil {
			return err
		}
		// Receive unchoke message
		if _, err := peer.Recv(Unchoke); err != nil {
			return err
		}

		peers[i] = peer
	}

	// Create a temporary file in the current directory to store the downloaded pieces
	f, err := os.Create("./temp_download_file")
	if err != nil {
		return err
	}
	defer f.Close()

	// Set the file size to the length of the file being downloaded
	if err := f.Truncate(int64(t.Info.Length)); err != nil {
		return err
	}

	var g errgroup.Group
	// Limit concurrency with the number of peers (each peer downloads one piece at a time)
	g.SetLimit(len(peers))

	// Create a mutex to serialize access to the file
	var mu sync.Mutex

	// Iterate through all the pieces and download them
	piecesIter := t.Info.PiecesAll()
	piecesIter(func(n int, pieceHash []byte) bool {
		peer := peers[n%len(peers)]

		g.Go(func() error {
			// Lock the mutex to ensure only one peer writes to the file at a time
			mu.Lock()
			defer mu.Unlock()

			// Calculate the base offset for this piece
			baseOff := int64(uint64(n) * t.Info.PieceLength)
			pw := io.NewOffsetWriter(f, baseOff)

			// Download the piece
			plen, err := downloadPiece(peer, t, n, pw)
			if err != nil {
				return err
			}

			// Verify the downloaded piece's hash
			h := sha1.New()
			if _, err := io.Copy(h, io.NewSectionReader(f, baseOff, plen)); err != nil {
				return err
			}
			gotHash := h.Sum(nil)
			if !bytes.Equal(pieceHash, gotHash) {
				return fmt.Errorf("malformed piece %d: want hash %x, got %x", n, pieceHash, gotHash)
			}

			fmt.Printf("piece %d - %x\n", n, pieceHash)

			return nil
		})

		return true
	})

	// Wait for all the pieces to be downloaded
	if err := g.Wait(); err != nil {
		// Handle cleanup if something fails
		os.Remove(f.Name())
		return err
	}

	// After all download operations finish, close the file and move it to the final output path
	if err := f.Close(); err != nil {
		return err
	}

	// Move the temporary file to the final output path
	// finalPath := "/d/Code/Projects/Torrent/codecrafters-bittorrent-go/tmp/" + outPath
	if err := os.Rename(f.Name(), outPath); err != nil {
		return err
	}

	// Success message
	fmt.Printf("Downloaded %s to %s.\n", torrentFile, outPath)

	return nil
}

func downloadPiece(peer *Peer, t Tracker, piece int, pw io.WriterAt) (int64, error) {
	// block per piece rounded up
	blocksPerPiece := int((t.Info.PieceLength + maxBlockSize - 1) / maxBlockSize)

	for b := 0; b < blocksPerPiece; b++ {
		begin := uint32(b * maxBlockSize)
		blen := uint32(maxBlockSize)

		// the very last block (across all pieces) can be truncated, if file's length
		// doesn't perfectly align to the size of a block
		if total := uint64((piece + 1) * (b + 1) * int(blen)); total > t.Info.Length {
			blen = blen - uint32(total-t.Info.Length)
		}

		payload := RequestPayload{uint32(piece), begin, blen}
		if err := peer.Send(Request, payload); err != nil {
			return 0, err
		}
	}

	var plen int64
	for b := blocksPerPiece; b > 0; b-- {
		payload, err := peer.Recv(Piece)
		if err != nil {
			return 0, err
		}

		if p := binary.BigEndian.Uint32(payload[:]); p != uint32(piece) {
			return 0, fmt.Errorf("unexpected piece index %d", p)
		}

		begin := binary.BigEndian.Uint32(payload[4:])
		sz, err := pw.WriteAt(payload[8:], int64(begin))
		if err != nil {
			return 0, err
		}
		plen += int64(sz)
	}

	return plen, nil
}

func discoverPeers(t Tracker) ([]netip.AddrPort, error) {
	turl, err := trackerURLFrom(t)
	if err != nil {
		return nil, err
	}

	httpResp, err := http.Get(turl)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	var resp trackerResponse
	err = bencode.Unmarshal(httpResp.Body, &resp)
	if err != nil {
		return nil, err
	}

	return resp.Peers(), nil
}

func handshakePeer(t Tracker, peer *Peer) error {
	infoHash, err := t.InfoHash()
	if err != nil {
		return err
	}

	_, err = peer.Handshake(infoHash)
	return err
}

type Tracker struct {
	// Announce is a URL to a tracker.
	Announce string
	// Info contains metainfo of a tracker.
	Info TrackerInfo
}

func newTrackerFromPath(path string) (t Tracker, err error) {
	f, err := os.Open(path)
	if err != nil {
		return t, err
	}
	defer f.Close()

	err = bencode.Unmarshal(f, &t)
	return t, err
}

type TrackerInfo struct {
	// Name is a suggested name to save the file or directory as.
	Name string `bencode:"name"`
	// PieceLength is the number of bytes in each piece the file is split into.
	PieceLength uint64 `bencode:"piece length"`
	// Pieces is a string of multiple of 20. It is to be subdivided into strings of length 20,
	// each of which is the SHA1 hash of the piece at the corresponding index.
	Pieces string `bencode:"pieces"`
	// Length is the size of the file in bytes, for single-file torrents
	Length uint64 `bencode:"length"`
}

func (info TrackerInfo) PiecesAll() func(func(int, []byte) bool) {
	return func(yield func(int, []byte) bool) {
		var n int
		for p := []byte(info.Pieces); len(p) > 0; p = p[20:] {
			if !yield(n, p[:20]) {
				return
			}
			n++
		}
	}
}

func (info TrackerInfo) PiecesTotal() int {
	return len(info.Pieces) % 20
}

func (t Tracker) InfoHash() ([]byte, error) {
	h := sha1.New()
	err := bencode.Marshal(h, t.Info)
	if err != nil {
		return nil, err
	}
	ret := h.Sum(nil)
	return ret[:], nil
}

func trackerURLFrom(t Tracker) (string, error) {
	u, err := url.Parse(t.Announce)
	if err != nil {
		return "", nil
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", nil
	}
	// the info hash of the torrent file
	infoHash, err := t.InfoHash()
	if err != nil {
		return "", nil
	}
	q.Add("info_hash", string(infoHash))
	// a unique identifier for your client
	q.Add("peer_id", "00112233445566778899")
	// the port your client is listening on
	q.Add("port", "6881")
	// the total amount uploaded so far (always 0)
	q.Add("uploaded", "0")
	// the total amount downloaded (always 0)
	q.Add("downloaded", "0")
	// the number of bytes left to download
	left := strconv.FormatUint(t.Info.Length, 10)
	q.Add("left", left)
	// whether the peer list should use the compact representation (always 1)
	q.Add("compact", "1")

	u.RawQuery = q.Encode()

	return u.String(), nil
}

type trackerResponse struct {
	Interval uint64 `bencode:"interval"`
	RawPeers string `bencode:"peers"`
}

func (tr trackerResponse) Peers() []netip.AddrPort {
	rawPeers := []byte(tr.RawPeers)
	peers := make([]netip.AddrPort, 0, len(rawPeers)/6)
	for len(rawPeers) > 0 {
		addr, _ := netip.AddrFromSlice(rawPeers[:4])
		port := binary.BigEndian.Uint16(rawPeers[4:])
		peers = append(peers, netip.AddrPortFrom(addr, port))
		rawPeers = rawPeers[6:]
	}
	return peers
}
