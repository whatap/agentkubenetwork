package whatap

import (
	"context"
	"net"
	"testing"

	"github.com/whatap/golib/util/hash"
)

func TestHandshakeAcceptsHeaderEchoOfIssuedTransferKey(t *testing.T) {
	cfg := testConfig()
	collector := startCollector(t, func(conn net.Conn) error {
		if err := collectorHello(conn, cfg); err != nil {
			return err
		}
		reply := collectorFrame(4, 0xff, testPcode, hash.HashStr(cfg.ObjectName), testTransfer,
			collectorEncrypt([]byte(testMasterKey), collectorKeyPlain()))
		if _, err := conn.Write(reply); err != nil {
			return err
		}
		_, err := collectorPack(conn, cfg)
		return err
	})
	clientCfg := cfg
	clientCfg.Servers = []string{collector.address()}
	client := testClient(t, clientCfg)
	if err := client.Send(context.Background(), testPack(12345)); err != nil {
		t.Fatalf("valid issued transfer key echoed by collector was rejected: %v", err)
	}
	collector.wait(t)
}
