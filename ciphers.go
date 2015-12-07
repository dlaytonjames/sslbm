//

// package sslbenchmark

package sslbenchmark

import "errors"

type Ciphers struct {
	CipherMap map[string]uint16
}

func (ciphers *Ciphers) ciphers(inputcipher []string) ([]uint16, error) {
	var tmpcipher []uint16
	for _, c := range inputcipher {
		if hx, exist := ciphers.CipherMap[c]; exist {
			tmpcipher = append(tmpcipher, hx)
		}
	}
	if len(tmpcipher) == 0 {
		return tmpcipher, errors.New("not support")
	}
	return tmpcipher, nil
}
