package logging

import (
	"net"
	"time"
)

//go:generate go run generate_multiplexer.go ConnectionTracer connection_tracer.go multiplexer.tmpl connection_tracer_multiplexer.go

// A ConnectionTracer records events.
type ConnectionTracer struct {
	StartedConnection                func(local, remote net.Addr, srcConnID, destConnID ConnectionID)
	NegotiatedVersion                func(chosen Version, clientVersions, serverVersions []Version)
	ClosedConnection                 func(err error)
	SentTransportParameters          func(parameters *TransportParameters)
	ReceivedTransportParameters      func(parameters *TransportParameters)
	RestoredTransportParameters      func(parameters *TransportParameters) // for 0-RTT
	SentLongHeaderPacket             func(hdr *ExtendedHeader, size ByteCount, ecn ECN, ack *AckFrame, frames []Frame)
	SentShortHeaderPacket            func(hdr *ShortHeader, size ByteCount, ecn ECN, ack *AckFrame, frames []Frame)
	ReceivedVersionNegotiationPacket func(dest, src ArbitraryLenConnectionID, versions []Version)
	ReceivedRetry                    func(hdr *Header)
	ReceivedLongHeaderPacket         func(hdr *ExtendedHeader, size ByteCount, ecn ECN, frames []Frame)
	ReceivedShortHeaderPacket        func(hdr *ShortHeader, size ByteCount, ecn ECN, frames []Frame)
	BufferedPacket                   func(packetType PacketType, size ByteCount)
	DroppedPacket                    func(packetType PacketType, pn PacketNumber, size ByteCount, reason PacketDropReason)
	UpdatedMetrics                   func(rttStats *RTTStats, cwnd, bytesInFlight ByteCount, packetsInFlight int)
	AcknowledgedPacket               func(encLevel EncryptionLevel, pn PacketNumber)
	LostPacket                       func(encLevel EncryptionLevel, pn PacketNumber, reason PacketLossReason)
	UpdatedMTU                       func(mtu ByteCount, done bool)
	UpdatedCongestionState           func(state CongestionState)
	UpdatedPTOCount                  func(value uint32)
	UpdatedKeyFromTLS                func(encLevel EncryptionLevel, p Perspective)
	UpdatedKey                       func(keyPhase KeyPhase, remote bool)
	DroppedEncryptionLevel           func(encLevel EncryptionLevel)
	DroppedKey                       func(keyPhase KeyPhase)
	SetLossTimer                     func(timerType TimerType, encLevel EncryptionLevel, time time.Time)
	LossTimerExpired                 func(timerType TimerType, encLevel EncryptionLevel)
	LossTimerCanceled                func()
	ECNStateUpdated                  func(state ECNState, trigger ECNStateTrigger)
	ChoseALPN                        func(protocol string)
	// CreatedIncomingStreams is called when one or more incoming stream objects are
	// created to satisfy a peer-initiated stream frame. gap is the number of stream
	// objects created (in StreamNum space, i.e. increments of 1 per stream, not 4).
	// A gap greater than 1 means intermediate streams were allocated to satisfy
	// RFC 9000 §3.2 ordering requirements.
	CreatedIncomingStreams func(streamType StreamType, gap StreamNum)
	// Close is called when the connection is closed.
	Close func()
	Debug func(name, msg string)
}
