package proxy

import (
	"context"
	"log"
	"net/http"

	"thinkpol-vpn/interface/api/protobuf"

	"github.com/gorilla/websocket"

	"google.golang.org/protobuf/proto"
)

type RawWebSocketVpnProxy struct {
	upgrader *websocket.Upgrader

	// TODO: rethink
	send_chan    chan *protobuf.PacketV4
	recieve_chan chan *protobuf.PacketV4
	conn         *websocket.Conn
	cancel       *context.CancelFunc
}

func NewRawWebSocketVpnProxy() *RawWebSocketVpnProxy {
	upgrader := websocket.Upgrader{}

	transport := RawWebSocketVpnProxy{
		upgrader:     &upgrader,
		send_chan:    make(chan (*protobuf.PacketV4), 1),
		recieve_chan: make(chan (*protobuf.PacketV4), 1),
	}

	return &transport
}

func (transport *RawWebSocketVpnProxy) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	transport.cancel = &cancel

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Println("websocket read handler stopped")
				return
			default:
				break
			}

			if transport.conn == nil {
				continue
			}

			mt, message, err := transport.conn.ReadMessage()
			if err != nil {
				log.Println("socket read error", err)
				return
			}
			if mt != websocket.BinaryMessage {
				log.Println("unsupported mt")
				return
			}

			var packet *protobuf.PacketV4
			err = proto.Unmarshal(message, packet)

			log.Println("successfully unmarshaled packet")

			transport.recieve_chan <- packet

			log.Println("sent packet to recieve_chan")
		}
	}()

	go func() {
		for {
			var packet *protobuf.PacketV4

			select {
			case <-ctx.Done():
				log.Println("websocket write handler stopped")
				return
			case packet = <-transport.send_chan:
			}

			message, err := proto.Marshal(packet)
			if err != nil {
				log.Println("error marshaling packet", err)
				return
			}

			log.Println("successfully marshaled packet")

			err = transport.conn.WriteMessage(websocket.BinaryMessage, message)

			if err != nil {
				log.Println("error sending message", err)
				return
			}

			log.Println("sent packet to transport")
		}
	}()
}

func (transport *RawWebSocketVpnProxy) Stop() {
	if transport.cancel != nil {
		(*transport.cancel)()
	}

	if transport.conn != nil {
		transport.conn.Close()
	}

	transport.conn = nil
	transport.cancel = nil
}

func (transport *RawWebSocketVpnProxy) UpgradeConnection(w http.ResponseWriter, r *http.Request) {
	if transport.conn != nil {
		http.Error(w, "already taken", 418)
	}

	conn, err := transport.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}

	transport.conn = conn
	transport.conn.SetCloseHandler(func(code int, text string) error {
		transport.Stop()
		transport.Start()
		return nil
	})
}

func (transport *RawWebSocketVpnProxy) SendToTransport(len int, buf []byte) {
	if transport.conn == nil {
		log.Println("[WARN] nowhere to send new packets - dropping")
		return
	}

	var length int32 = int32(len)
	compactBuffer := buf[:len]

	packet := protobuf.PacketV4{
		Length: &length,
		Buffer: compactBuffer,
	}

	log.Println("add packet to send_chan")

	transport.send_chan <- &packet
}
