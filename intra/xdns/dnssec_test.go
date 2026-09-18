package xdns

import (
	"context"
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestValidateChainRejectsUnsignedAndMixedAnswers(t *testing.T) {
	if got, err := ValidateChain(context.Background(), nil, "example.com.", []dns.RR{&dns.A{}}, nil); err == nil || got != ResultIndeterminate {
		t.Fatalf("unsigned answer: got %s, err %v", got, err)
	}
}

func TestVerifyRRSIGSet(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	private, err := key.Generate(1024)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		t.Fatalf("generated key is %T, not crypto.Signer", private)
	}
	rr := &dns.DNSKEY{
		Hdr:       key.Hdr,
		Flags:     key.Flags,
		Protocol:  key.Protocol,
		Algorithm: key.Algorithm,
		PublicKey: key.PublicKey,
	}
	now := time.Now().UTC()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   key.Algorithm,
		Labels:      2,
		OrigTtl:     3600,
		Expiration:  uint32(now.Add(time.Hour).Unix()),
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  "example.com.",
	}
	if err := sig.Sign(signer, []dns.RR{rr}); err != nil {
		t.Fatal(err)
	}
	if got, err := verifyRRSIGSet([]dns.RR{rr}, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}); got != ResultSecure || err != nil {
		t.Fatalf("valid signature: got %s, err %v", got, err)
	}
	sig.Signature = strings.Repeat("A", len(sig.Signature))
	if got, err := verifyRRSIGSet([]dns.RR{rr}, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}); got != ResultBogus || err == nil {
		t.Fatalf("forged signature: got %s, err %v", got, err)
	}
}

func TestMatchAndVerifyKeySetRequiresDNSKEYSignature(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	private, err := key.Generate(1024)
	if err != nil {
		t.Fatal(err)
	}
	signer := private.(crypto.Signer)
	ds := key.ToDS(dns.SHA256)
	rrset := []dns.RR{key}
	now := time.Now().UTC()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   key.Algorithm,
		Labels:      2,
		OrigTtl:     3600,
		Expiration:  uint32(now.Add(time.Hour).Unix()),
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  "example.com.",
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatal(err)
	}
	if _, err := matchAndVerifyKeySet("example.com.", []*dns.DNSKEY{key}, []*dns.RRSIG{sig}, []*dns.DS{ds}); err != nil {
		t.Fatalf("valid DNSKEY proof: %v", err)
	}
	if _, err := matchAndVerifyKeySet("example.com.", []*dns.DNSKEY{key}, nil, []*dns.DS{ds}); err == nil {
		t.Fatal("missing DNSKEY signature was accepted")
	}
}
