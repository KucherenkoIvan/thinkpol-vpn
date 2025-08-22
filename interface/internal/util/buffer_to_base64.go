package util

import "encoding/base64"

func BufferToBase64(buf []byte) string {
	encodedString := base64.StdEncoding.EncodeToString(buf)

	return encodedString
}
