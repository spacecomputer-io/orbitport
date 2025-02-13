package providers

// RandSource indicates the source of randomness
type RandSource int

// DefaultSources is the default list of sources to use (only Aptos Orbital source is used by default)
var DefaultSources = []RandSource{RandSourceAptosOrbital}

const (
	RandSourceUnknown RandSource = iota
	RandSourceLocalGoCrypto
	RandSourceLocalDrivedFromSpaceSeed
	RandSourceAptosOrbital
)

var randSourceName = map[RandSource]string{
	RandSourceUnknown:                  "",
	RandSourceLocalGoCrypto:            "local/go_crypto",
	RandSourceAptosOrbital:             "space/aptos_orbital",
	RandSourceLocalDrivedFromSpaceSeed: "local/space_seed",
}

func (r RandSource) String() string {
	return randSourceName[r]
}

// RandSourceFromString returns the RandSource from a string
func RandSourceFromString(s string) RandSource {
	for k, v := range randSourceName {
		if v == s {
			return k
		}
	}
	return RandSourceUnknown
}

// RandSourceFromStrings returns the RandSource from a list of strings
func RandSourceFromStrings(sources []string) []RandSource {
	var res []RandSource
	for _, s := range sources {
		res = append(res, RandSourceFromString(s))
	}
	return res
}
