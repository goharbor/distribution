package fixtures

import "strings"

func identifiers(hostname, other, clusterName, uuidString, certAlias string) bool {
	// ruleid: go-case-sensitive-network-name
	_ = hostname == other
	// ruleid: go-case-sensitive-network-name
	_ = other != hostname
	// ok: go-case-sensitive-network-name
	_ = hostname == ""
	// ok: go-case-sensitive-network-name
	_ = strings.EqualFold(hostname, other)
	// ruleid: go-network-name-case-discard
	hostname = strings.ToLower(other)
	// ok: go-network-name-case-discard
	comparisonKey := strings.ToLower(hostname)
	// ruleid: go-cluster-name-case-fold
	_ = strings.ToUpper(clusterName)
	// ruleid: go-cluster-name-case-fold
	_ = strings.EqualFold(clusterName, other)
	// ok: go-cluster-name-case-fold
	_ = clusterName == other
	// ruleid: go-case-sensitive-uuid-text
	_ = uuidString == other
	// ok: go-case-sensitive-uuid-text
	_ = uuidString != ""
	// ok: go-case-sensitive-uuid-text
	_ = strings.EqualFold(uuidString, other)
	// ruleid: go-case-sensitive-certificate-alias
	_ = certAlias == other
	// ok: go-case-sensitive-certificate-alias
	_ = strings.EqualFold(certAlias, other)
	return comparisonKey != ""
}

func uuidValues(uuid [16]byte, other [16]byte) bool {
	// ok: go-case-sensitive-uuid-string, go-case-sensitive-uuid-text
	return uuid == other
}

func uuidText(uuid interface{ String() string }, other string) bool {
	// ruleid: go-case-sensitive-uuid-string
	return uuid.String() == other
}

func normalizeHostname(value string) {
	// ruleid: go-network-name-case-discard
	hostname := strings.ToLower(value)
	_ = hostname
}
