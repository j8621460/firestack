// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package xdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidateChain is an opt-in, positive-answer DNSSEC validator. It does not
// validate denial-of-existence proofs, so callers must treat ResultIndeterminate
// as unvalidated and must never use the upstream AD bit as independent proof.
// All DNSKEY and DS lookups are made through Resolver, which must use the same
// authenticated transport as the original query.

// RootTrustAnchors holds the IANA root zone KSK(s) as DS records.
// IANA runs old + new anchors concurrently during an RFC 5011 rollover,
// so a validator must accept a match against ANY entry here.
var RootTrustAnchors = []*dns.DS{
	{ // KSK-2017, key tag 20326, in the root zone since the 2018 rollover.
		// VERIFY against root-anchors.xml before relying on this.
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     20326,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	},
	// TODO: add the KSK-2024 successor (reported key tag 38696) once you've
	// confirmed its digest yourself -- IANA began that rollover in 2025/26
	// and by the time this merges the root may only publish the new key.
}

// Resolver is the minimal upstream lookup capability the validator needs
// for its own DNSKEY/DS queries. Implement this as a thin adapter over
// your existing dnsx.Transport so these lookups go over the same trusted
// channel as the original query.
type Resolver interface {
	Query(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// Result mirrors the RFC 4035 §4.3 validator states. Deliberately not a
// bool: collapsing "bogus" (signature/hash failed -- actively hostile) into
// the same value as "insecure" (zone is legitimately unsigned) is exactly
// the kind of fail-open bug this file exists to avoid.
type Result int

const (
	ResultInsecure Result = iota
	ResultSecure
	ResultBogus
	ResultIndeterminate
)

func (r Result) String() string {
	switch r {
	case ResultSecure:
		return "secure"
	case ResultBogus:
		return "bogus"
	case ResultInsecure:
		return "insecure"
	default:
		return "indeterminate"
	}
}

// ValidateChain verifies rrsigs (as returned alongside rrset by the
// original upstream answer) up to a RootTrustAnchors entry, fetching
// each ancestor zone's DNSKEY/DS via r along the way.
//
// Callers: a non-ResultSecure return means "do not treat this answer as
// DNSSEC-validated" -- on ResultBogus specifically, callers should treat
// the answer the same as SERVFAIL, since it means something signed data
// that doesn't match what a trusted key actually signed.
func ValidateChain(ctx context.Context, r Resolver, qname string, rrset []dns.RR, rrsigs []*dns.RRSIG) (Result, error) {
	if ctx == nil {
		return ResultIndeterminate, errors.New("dnssec: nil context")
	}
	if r == nil {
		return ResultIndeterminate, errors.New("dnssec: nil resolver")
	}
	if len(rrset) == 0 || len(rrsigs) == 0 {
		return ResultIndeterminate, errors.New("dnssec: answer has no signed RRset")
	}
	if qname == "" {
		return ResultIndeterminate, errors.New("dnssec: empty query name")
	}
	if !validRRSet(rrset) {
		return ResultBogus, errors.New("dnssec: invalid or mixed RRset")
	}

	zone := dns.Fqdn(rrsigs[0].SignerName)
	keys, res, err := verifiedKeysFor(ctx, r, zone)
	if err != nil {
		return ResultIndeterminate, fmt.Errorf("dnssec: chain walk to %q: %w", zone, err)
	}
	if res != ResultSecure {
		return res, nil // insecure or bogus higher up the chain
	}

	now := time.Now().UTC()
	var lastErr error
	for _, sig := range rrsigs {
		if sig == nil || sig.TypeCovered != rrset[0].Header().Rrtype || !strings.EqualFold(dns.Fqdn(sig.SignerName), zone) {
			continue
		}
		key := findKey(keys, sig.KeyTag, sig.Algorithm)
		if key == nil {
			lastErr = fmt.Errorf("dnssec: no DNSKEY for keytag %d alg %d in %s", sig.KeyTag, sig.Algorithm, zone)
			continue
		}
		if !sig.ValidityPeriod(now) {
			lastErr = fmt.Errorf("dnssec: RRSIG for %s outside validity window", qname)
			continue
		}
		if err := sig.Verify(key, rrset); err != nil {
			lastErr = fmt.Errorf("dnssec: RRSIG verify failed for %s: %w", qname, err)
			continue
		}
		return ResultSecure, nil
	}
	if lastErr != nil {
		return ResultBogus, lastErr
	}
	return ResultBogus, errors.New("dnssec: no RRSIG validated")
}

// verifiedKeysFor walks the chain of trust from the root down to zone,
// returning zone's own DNSKEY RRset once every delegation in between has
// been checked (DS at the parent matches a DNSKEY at the child, and that
// DNSKEY RRset's own RRSIG verifies against it).
func verifiedKeysFor(ctx context.Context, r Resolver, zone string) ([]*dns.DNSKEY, Result, error) {
	labels := dns.SplitDomainName(zone)
	// Build the list of zone cuts from root (".") down to the target,
	// e.g. example.com. -> [".", "com.", "example.com."]
	cuts := []string{"."}
	for i := len(labels) - 1; i >= 0; i-- {
		cuts = append(cuts, dns.Fqdn(strings.Join(labels[i:], ".")))
	}

	trustedDS := RootTrustAnchors
	var trustedKeys []*dns.DNSKEY

	for _, cut := range cuts {
		keys, keySigs, err := queryDNSKEY(ctx, r, cut)
		if err != nil {
			return nil, ResultIndeterminate, fmt.Errorf("DNSKEY(%s): %w", cut, err)
		}
		if len(keys) == 0 || len(keySigs) == 0 {
			return nil, ResultIndeterminate, fmt.Errorf("DNSKEY(%s): incomplete signed response", cut)
		}

		matched, verifyErr := matchAndVerifyKeySet(cut, keys, keySigs, trustedDS)
		if verifyErr != nil {
			return nil, ResultBogus, verifyErr
		}
		trustedKeys = matched

		if cut == zone {
			return trustedKeys, ResultSecure, nil
		}

		// Fetch the child's DS record set (held at the parent, signed by
		// the parent's ZSK) to carry trust down one more label.
		child := nextCut(cuts, cut)
		ds, dsSigs, err := queryDS(ctx, r, child)
		if err != nil {
			return nil, ResultIndeterminate, fmt.Errorf("DS(%s): %w", child, err)
		}
		if len(ds) == 0 || len(dsSigs) == 0 {
			// Without NSEC/NSEC3 denial-of-existence validation, an empty DS
			// answer is not proof that the delegation is unsigned.
			return nil, ResultIndeterminate, fmt.Errorf("DS(%s): missing signed delegation", child)
		}
		dsRRset := make([]dns.RR, len(ds))
		for i, record := range ds {
			dsRRset[i] = record
		}
		if res, err := verifyRRSIGSet(dsRRset, dsSigs, trustedKeys); err != nil || res != ResultSecure {
			if err == nil {
				err = errors.New("no valid RRSIG over DS RRset")
			}
			return nil, ResultBogus, fmt.Errorf("DS(%s) signature: %w", child, err)
		}
		trustedDS = ds
	}
	return nil, ResultIndeterminate, errors.New("dnssec: walked off the end of the chain")
}

func matchAndVerifyKeySet(zone string, keys []*dns.DNSKEY, sigs []*dns.RRSIG, trustedDS []*dns.DS) ([]*dns.DNSKEY, error) {
	if len(keys) == 0 || len(sigs) == 0 || len(trustedDS) == 0 {
		return nil, fmt.Errorf("dnssec: incomplete DNSKEY proof for %s", zone)
	}
	var ksks []*dns.DNSKEY
	for _, k := range keys {
		for _, ds := range trustedDS {
			if candidate := k.ToDS(ds.DigestType); candidate != nil &&
				strings.EqualFold(candidate.Digest, ds.Digest) &&
				candidate.KeyTag == ds.KeyTag {
				ksks = append(ksks, k)
			}
		}
	}
	if len(ksks) == 0 {
		return nil, fmt.Errorf("dnssec: no DNSKEY in %s matches a trusted DS", zone)
	}
	keyRRset := make([]dns.RR, len(keys))
	for i, key := range keys {
		keyRRset[i] = key
	}
	if res, err := verifyRRSIGSet(keyRRset, sigs, ksks); res != ResultSecure {
		if err == nil {
			err = errors.New("no valid RRSIG over DNSKEY RRset")
		}
		return nil, fmt.Errorf("dnssec: DNSKEY RRset for %s is not signed by a DS-matched key: %w", zone, err)
	}
	// Return the complete DNSKEY RRset: the KSK proved the set, and its ZSKs
	// are needed to validate ordinary data signatures below this zone.
	return keys, nil
}

func validRRSet(rrset []dns.RR) bool {
	if len(rrset) == 0 || rrset[0] == nil || rrset[0].Header() == nil {
		return false
	}
	h := rrset[0].Header()
	for _, rr := range rrset {
		if rr == nil || rr.Header() == nil || rr.Header().Rrtype != h.Rrtype || rr.Header().Class != h.Class || !strings.EqualFold(rr.Header().Name, h.Name) {
			return false
		}
	}
	return true
}

func verifyRRSIGSet(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY) (Result, error) {
	now := time.Now().UTC()
	for _, sig := range sigs {
		key := findKey(keys, sig.KeyTag, sig.Algorithm)
		if key == nil || !sig.ValidityPeriod(now) {
			continue
		}
		if err := sig.Verify(key, rrset); err == nil {
			return ResultSecure, nil
		}
	}
	return ResultBogus, errors.New("dnssec: no valid RRSIG over RRset")
}

func findKey(keys []*dns.DNSKEY, tag uint16, alg uint8) *dns.DNSKEY {
	for _, k := range keys {
		if k.KeyTag() == tag && k.Algorithm == alg {
			return k
		}
	}
	return nil
}

func nextCut(cuts []string, cur string) string {
	for i, c := range cuts {
		if c == cur && i+1 < len(cuts) {
			return cuts[i+1]
		}
	}
	return cur
}

// queryDNSKEY and queryDS issue DO-bit queries over r and split the response
// into records and signatures. Resolver is deliberately injected so callers
// cannot accidentally make trust-chain lookups over plaintext DNS.
func queryDNSKEY(ctx context.Context, r Resolver, zone string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeDNSKEY)
	msg.SetEdns0(4096, true) // DO bit set
	ans, err := r.Query(ctx, msg)
	if err != nil {
		return nil, nil, err
	}
	var keys []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range ans.Answer {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			if strings.EqualFold(dns.Fqdn(v.Hdr.Name), dns.Fqdn(zone)) {
				keys = append(keys, v)
			}
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDNSKEY && strings.EqualFold(dns.Fqdn(v.SignerName), dns.Fqdn(zone)) {
				sigs = append(sigs, v)
			}
		}
	}
	return keys, sigs, nil
}

func queryDS(ctx context.Context, r Resolver, zone string) ([]*dns.DS, []*dns.RRSIG, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeDS)
	msg.SetEdns0(4096, true)
	ans, err := r.Query(ctx, msg)
	if err != nil {
		return nil, nil, err
	}
	var ds []*dns.DS
	var sigs []*dns.RRSIG
	for _, rr := range ans.Answer {
		switch v := rr.(type) {
		case *dns.DS:
			ds = append(ds, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDS {
				sigs = append(sigs, v)
			}
		}
	}
	return ds, sigs, nil
}
