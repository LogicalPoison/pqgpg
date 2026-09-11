package armor

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func Encode(data []byte, typ string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("-----BEGIN PQGPG %s-----\n", typ))
	b.WriteString("Version: pqgpg-go 0.1\n")
	b.WriteString("Comment: Post-Quantum GPG (pure Go / CIRCL)\n\n")
	enc := base64.StdEncoding.EncodeToString(data)
	for i := 0; i < len(enc); i += 64 {
		end := i + 64
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	b.WriteString(fmt.Sprintf("-----END PQGPG %s-----\n", typ))
	return b.String()
}

func Decode(armored string) ([]byte, error) {
	lines := strings.Split(armored, "\n")
	var b64 strings.Builder
	inBody := false
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "-----BEGIN PQGPG ") {
			inBody = false
			continue
		}
		if strings.HasPrefix(line, "-----END PQGPG ") {
			break
		}
		if line == "" {
			inBody = true
			continue
		}
		if !inBody {
			continue // header lines
		}
		if strings.HasPrefix(line, "=") {
			continue // checksum line (ignored)
		}
		b64.WriteString(strings.TrimSpace(line))
	}
	return base64.StdEncoding.DecodeString(b64.String())
}
