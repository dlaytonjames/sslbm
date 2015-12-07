//

// package sslbenchmark

package sslbenchmark

import "fmt"

type HeaderSlice []string

func (h *HeaderSlice) String() string {
	return fmt.Sprintf("%s", *h)
}

func (h *HeaderSlice) Set(str string) error {
	if str != "" {
		*h = append(*h, str)
	}
	return nil
}

/*

type Value interface {
	String() string
	Set(string) error
}
func main(){
	var headers HeaderSlice
	flag.Var(&headers, "header", "request header")
	flag.Parse()
	for i := 0; i < len(headers); i++ {
		fmt.Printf("%s\n", headers[i])
	}
}
*/
