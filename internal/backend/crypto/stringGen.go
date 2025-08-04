package crypto

import (
	"crypto/rand"
	"math"
)

const (
	// STDLEN is a standard length of  string to achive ~95 bits of entropy.
	STD_LEN = 16
	// UUIDLEN is a length of  string to achive ~119 bits of entropy, closest
	// to what can be losslessly converted to UUIDv4 (122 bits).
	UUID_LEN = 20

	// MAXBUFLEN is the maximum length of a temporary buffer for random bytes.
	MAX_BUF_LEN = 2048

	// MINREGENBUFLEN is the minimum length of temporary buffer for random bytes
	// to fill after the first rand.Read request didn't produce the full result.
	// If the initial buffer is smaller, this value is ignored.
	// Rationale: for performance, assume it's pointless to request fewer bytes from rand.Read.
	MIN_REGEN_BUF_LEN = 16
)

// StdChars is a set of standard characters allowed in  string.
var StdChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@!#&?*={}[]+-1234567890")

// NewLen returns a new random string of the provided length, consisting of
// standard characters.
func GenerateRandomString(length int) string {
	return newLenChars(length, StdChars)
}

// estimatedBufLen returns the estimated number of random bytes to request
// given that byte values greater than maxByte will be rejected.
func estimatedBufLen(need, maxByte int) int {
	return int(math.Ceil(float64(need) * (255 / float64(maxByte))))
}

// NewLenCharsBytes returns a new random byte slice of the provided length, consisting
// of the provided byte slice of allowed characters (maximum 256).
func newLenCharsBytes(length int, chars []byte) []byte {
	if length == 0 {
		return nil
	}
	clen := len(chars)
	if clen < 2 || clen > 256 {
		panic(": wrong charset length for NewLenChars")
	}
	maxrb := 255 - (256 % clen)
	buflen := estimatedBufLen(length, maxrb)
	if buflen < length {
		buflen = length
	}
	if buflen > MAX_BUF_LEN {
		buflen = MAX_BUF_LEN
	}
	buf := make([]byte, buflen) // storage for random bytes
	out := make([]byte, length) // storage for result
	i := 0
	for {
		if _, err := rand.Read(buf[:buflen]); err != nil {
			panic(": error reading random bytes: " + err.Error())
		}
		for _, rb := range buf[:buflen] {
			c := int(rb)
			if c > maxrb {
				// Skip this number to avoid modulo bias.
				continue
			}
			out[i] = chars[c%clen]
			i++
			if i == length {
				return out
			}
		}
		// Adjust new requested length, but no smaller than MINREGENBUFLEN.
		buflen = estimatedBufLen(length-i, maxrb)
		if buflen < MIN_REGEN_BUF_LEN && MIN_REGEN_BUF_LEN < cap(buf) {
			buflen = MIN_REGEN_BUF_LEN
		}
		if buflen > MAX_BUF_LEN {
			buflen = MAX_BUF_LEN
		}
	}
}

// NewLenChars returns a new random string of the provided length, consisting
// of the provided byte slice of allowed characters (maximum 256).
func newLenChars(length int, chars []byte) string {
	return string(newLenCharsBytes(length, chars))
}
