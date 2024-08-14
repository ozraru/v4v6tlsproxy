package internal

import (
	"context"
	"io"
	"log/slog"
	"net"

	"github.com/google/uuid"
	"github.com/ozraru/v4v6tlsproxy/internal/logw"
)

func handle(ctx context.Context, conn *net.TCPConn) {
	connId := uuid.Must(uuid.NewV7())
	ctx = logw.With(ctx, logw.Get(ctx).With(slog.String("conn_id", connId.String())))

	logw.Get(ctx).Debug("Handling connection: ", slog.String("from", conn.RemoteAddr().String()))
	defer logw.Get(ctx).Debug("Handling connection: ", slog.String("from", conn.RemoteAddr().String()))

	defer conn.Close()

	hostname, buf := parseInitialPacket(ctx, conn)

	if hostname == "" {
		logw.Get(ctx).Debug("Closing no valid hostname connection")
		return
	}

	logw.Get(ctx).Debug("checking IsAllowed")

	if !IsAllowed(ctx, hostname) {
		logw.Get(ctx).Warn("remote not allowed", slog.String("hostname", hostname))
		return
	}

	destAddr, err := net.ResolveIPAddr("ip6", hostname)
	if err != nil {
		logw.Get(ctx).Warn("Failed to resolve address", slog.Any("error", err))
		return
	}

	logw.Get(ctx).Debug("checking IsDenied")

	if IsDenied(destAddr) {
		logw.Get(ctx).Warn("remote denied", slog.Any("address", destAddr))
		return
	}

	destAddrPort := &net.TCPAddr{
		IP:   destAddr.IP,
		Port: Config.Network.RemotePort,
		Zone: destAddr.Zone,
	}

	logw.Get(ctx).Debug("generate source address", slog.String("dest_addr", destAddrPort.String()))

	var srcAddrPort *net.TCPAddr
	if Config.Network.UseAddressConversion {
		originalAddr := conn.RemoteAddr().(*net.TCPAddr)
		convertedAddr := Config.Network.DialSourceAddress.AsSlice()
		copy(convertedAddr[12:16], originalAddr.IP)
		srcAddrPort = &net.TCPAddr{
			IP: convertedAddr[:],
		}
	} else {
		if Config.Network.DialSourceAddress.IsValid() {
			srcAddrPort = &net.TCPAddr{
				IP: Config.Network.DialSourceAddress.AsSlice(),
			}
		}
	}

	logw.Get(ctx).Debug("dial remote", slog.Any("dest_addr", destAddrPort))

	destConn, err := net.DialTCP("tcp6", srcAddrPort, destAddrPort)
	if err != nil {
		logw.Get(ctx).Warn("Failed to make remote connection", slog.Any("error", err))
		return
	}

	defer destConn.Close()

	logw.Get(ctx).Info("connection successful",
		slog.String("from", conn.RemoteAddr().String()),
		slog.String("self", destConn.LocalAddr().String()),
		slog.String("to", destConn.RemoteAddr().String()),
	)

	if _, err := destConn.Write(buf); err != nil {
		logw.Get(ctx).Debug("Failed to write initial packet to remote", slog.Any("error", err))
		return
	}

	copyCtx, cancel := context.WithCancel(ctx)

	go func() {
		_, err := io.Copy(destConn, conn)
		logw.Get(ctx).Debug("forward copy error", slog.Any("error", err))
		cancel()
	}()
	go func() {
		_, err := io.Copy(conn, destConn)
		logw.Get(ctx).Debug("reverse copy error", slog.Any("error", err))
		cancel()
	}()

	<-copyCtx.Done()
}

func parseInitialPacket(ctx context.Context, conn *net.TCPConn) (string, []byte) {

	buf := make([]byte, Config.HandshakeBuffer)
	bufUsed := 0

	n, err := io.ReadAtLeast(conn, buf[bufUsed:], 5)
	if err != nil {
		logw.Get(ctx).Debug("Failed to read first packet header: ", slog.Any("error", err))
		return "", buf[:bufUsed]
	}
	bufUsed += n

	processed := 0

	recordType := buf[0x0000]
	handshakeSize := (uint16(buf[0x0003]) << 8) + uint16(buf[0x0004])
	if recordType != 0x16 {
		logw.Get(ctx).Debug("invalid first packet record type")
		return "", buf[:bufUsed]
	}

	processed += 5

	if bufUsed < int(handshakeSize)+5 {
		n, err := io.ReadAtLeast(conn, buf[bufUsed:], int(handshakeSize)+5-bufUsed)
		if err != nil {
			logw.Get(ctx).Debug("Failed to read first packet: ", slog.Any("error", err))
			return "", buf[:bufUsed]
		}
		bufUsed += n
	}

	handshakeType := buf[processed]
	processed += 1

	if handshakeType != 0x01 {
		logw.Get(ctx).Debug("invalid first packet handshake type")
		return "", buf[:bufUsed]
	}

	processed += 3 + 2 + 32 // length, version, random

	sessionIdLength := int(buf[processed])
	processed += 1
	processed += sessionIdLength

	cipherSuitesLength := int(buf[processed])<<8 + int(buf[processed+1])
	processed += 2
	processed += cipherSuitesLength

	compressionMethodsLength := int(buf[processed])
	processed += 1
	processed += compressionMethodsLength

	extensionsLength := int(buf[processed])<<8 + int(buf[processed+1])
	processed += 2
	extensionsEnd := processed + extensionsLength

	for processed < extensionsEnd {
		extensionType := int(buf[processed])<<8 + int(buf[processed+1])
		processed += 2
		extensionLength := int(buf[processed])<<8 + int(buf[processed+1])
		processed += 2
		if extensionType != 0x0000 {
			processed += extensionLength
			continue
		}
		serverNameListLength := int(buf[processed])<<8 + int(buf[processed+1])
		serverNameListEnd := processed + serverNameListLength
		processed += 2
		for processed < serverNameListEnd {
			serverNameType := buf[processed]
			processed += 1
			serverNameLength := int(buf[processed])<<8 + int(buf[processed+1])
			processed += 2
			if serverNameType != 0x00 {
				processed += serverNameLength
				continue
			}
			logw.Get(ctx).Debug("server name found", slog.String("server_name", string(buf[processed:processed+serverNameLength])))
			return string(buf[processed : processed+serverNameLength]), buf[:bufUsed]
		}
	}
	logw.Get(ctx).Debug("server name not found")
	return "", buf[:bufUsed]
}
