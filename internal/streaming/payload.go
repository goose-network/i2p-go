// I2CP payload layer: the client payload (a streaming packet here) is
// always delivered to the remote destination gzip-compressed, with the
// protocol and ports smuggled into the gzip header — proto in the OS
// byte (offset 9), from/to ports in the two halves of the MTIME field
// (offsets 4-7). This is invisible to normal gzip decoders.
//
// Reference: I2PSessionMuxedImpl.prepPayload / setProto / setFromPort
// / setToPort, DataHelper.compress / decompress / zeroCompress.
package streaming

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

// Protocols carried in the payload OS byte. Reference:
// I2PSession.PROTO_*.
const (
	// ProtoStreaming is I2P streaming (this package).
	ProtoStreaming byte = 6
	// ProtoUnspecified means "no protocol given" (0xff in the header).
	ProtoUnspecified byte = 0xff
)

// Header byte offsets inside the gzip stream. Reference:
// I2PSessionMuxedImpl PROTO_BYTE / FROMPORT_BYTES / TOPORT_BYTES.
const (
	protoByte   = 9
	fromPortOff = 4
	toPortOff   = 6
)

// dontCompressSize is the threshold below which Java stores the data
// uncompressed in a stored-format gzip member (zeroCompress) but still
// wrapped in a valid gzip container. Reference:
// I2PSessionImpl2.DONT_COMPRESS_SIZE = 66.
const dontCompressSize = 66

// zeroCompressOverhead is the size of the stored-format wrapper.
const zeroCompressOverhead = 23

// CompressPayload gzips the payload and stamps proto and ports into
// the gzip header, exactly as I2PSessionMuxedImpl.prepPayload does.
// Small payloads use the stored (uncompressed) gzip member so the wire
// bytes match Java's zeroCompress output.
func CompressPayload(plain []byte, proto byte, fromPort, toPort uint16) ([]byte, error) {
	var out []byte
	if len(plain) <= dontCompressSize {
		out = zeroCompress(plain)
	} else {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if _, err := zw.Write(plain); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		out = buf.Bytes()
	}
	stampHeader(out, proto, fromPort, toPort)
	return out, nil
}

// stampHeader writes the proto/port bytes into a gzip header. Go's gzip
// writer emits MTIME=0 and OS=255 (unknown); we overwrite both.
func stampHeader(h []byte, proto byte, fromPort, toPort uint16) {
	h[fromPortOff] = byte(fromPort >> 8)
	h[fromPortOff+1] = byte(fromPort)
	h[toPortOff] = byte(toPort >> 8)
	h[toPortOff+1] = byte(toPort)
	h[protoByte] = proto
}

// DecompressPayload unpacks a received payload, returning the plain
// bytes plus the proto/ports from the header.
func DecompressPayload(b []byte) (plain []byte, proto byte, fromPort, toPort uint16, err error) {
	if len(b) < 10 {
		return nil, 0, 0, 0, fmt.Errorf("payload: short gzip %d", len(b))
	}
	if b[0] != 0x1f || b[1] != 0x8b {
		return nil, 0, 0, 0, fmt.Errorf("payload: bad gzip magic")
	}
	proto = b[protoByte]
	if proto == ProtoUnspecified {
		proto = 0
	}
	fromPort = binary.BigEndian.Uint16(b[fromPortOff:])
	toPort = binary.BigEndian.Uint16(b[toPortOff:])
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("payload: gunzip: %w", err)
	}
	plain, err = io.ReadAll(zr)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("payload: gunzip: %w", err)
	}
	return plain, proto, fromPort, toPort, nil
}

// zeroCompress wraps plain data in a stored (uncompressed) gzip
// member, byte-identical to Java's DataHelper.zeroCompress output:
//
//	[1f 8b 08 00 00 00 00 00 02 ff]     header (XFL=2, OS=ff)
//	[01 len16 data]                      stored deflate block (BTYPE=00)
//	[crc32(4)] [isize(4)]                trailer (both little-endian)
func zeroCompress(plain []byte) []byte {
	out := make([]byte, 0, zeroCompressOverhead+len(plain))
	// Header: magic(2) CM=deflate FLG=0 MTIME=0 XFL=2 OS=0xff.
	out = append(out, 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff)
	// Stored block: final bit, BTYPE=00, then LEN and NLEN little-endian.
	n := len(plain)
	out = append(out, 0x01, byte(n), byte(n>>8), ^byte(n), ^byte(n>>8))
	out = append(out, plain...)
	// Trailer: CRC32 of the data and the length (ISIZE), each 4 bytes
	// little-endian. Reference: DataHelper.zeroCompress toLongLE calls.
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(plain))
	out = binary.LittleEndian.AppendUint32(out, uint32(n))
	return out
}
