package app

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"testing/synctest"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/dns"
)

func dnsQueryEvent() collector.Event {
	e := retryEvent()
	e.Kind = collector.EventKindDNS
	e.Protocol = 17
	e.DestinationPort = 53
	e.PID = 42
	e.Payload = []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	return e
}

func TestRunEventsFinishesFreshDNSAsIncomplete(t *testing.T) {
	reader := newChannelEventReader()
	reader.events <- dnsQueryEvent()
	close(reader.events)
	var output bytes.Buffer
	if err := RunEvents(reader, &output, "node", 0, time.Now, nil, nil); err != nil {
		t.Fatal(err)
	}
	var transaction dns.Transaction
	if err := json.NewDecoder(&output).Decode(&transaction); err != nil {
		t.Fatalf("fresh query lost at EOF: %v", err)
	}
	if transaction.Outcome != dns.OutcomeIncomplete || transaction.Reason != dns.ReasonCaptureEnded {
		t.Fatalf("capture end mistaken for DNS timeout: %+v", transaction)
	}
}

func TestRunEventsExpiresDNSWithoutAnotherEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := newChannelEventReader()
		reader.events <- dnsQueryEvent()
		var output bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			result <- RunEventsWithOptions(ctx, reader, &output, "node", 0, time.Now, nil, nil, EventOptions{})
		}()
		synctest.Wait()
		time.Sleep(6 * time.Second)
		synctest.Wait()
		var transaction dns.Transaction
		if err := json.NewDecoder(bytes.NewReader(output.Bytes())).Decode(&transaction); err != nil {
			t.Errorf("idle DNS query never expired: %v", err)
		} else if transaction.Outcome != dns.OutcomeNoResponse {
			t.Errorf("wrong idle DNS outcome: %+v", transaction)
		}
		cancel()
		synctest.Wait()
		<-result
	})
}
