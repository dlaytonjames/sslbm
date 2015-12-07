//

// package sslbenchmark

package sslbenchmark

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type SSLBitch struct {
	IpAddress            string
	Port                 string
	DomainName           string
	ReqUrl               string
	Reqcipher            string
	Headers              HeaderSlice
	Conncurency          int
	Https                bool
	TCPRWTimeout         int
	DialTimeout          int
	OnlyHandShake        bool
	Insecure             bool
	KeepAliveTimeOUt     int
	SessionCacheCapacity int
	PreferServerSuites   bool
	SessionTicket        bool
	ReadBuffer           int
	SessionCache         bool
	KeepAlive            bool
	Verbose              bool
	ScanCipher           bool
	Pprofile             bool
	PproFileLog          string
	Duration             int
	DefaultCiphers       []uint16
	WG                   sync.WaitGroup
	TLSConfig            *tls.Config
	TCPDial              *net.Dialer
	CpuNum               int
}

func (sb *SSLBitch) BenchMark_HandShake() {
	if !sb.OnlyHandShake || !sb.Https || sb.ScanCipher {
		return
	}
	for count := 1; count <= sb.Conncurency; count++ {
		sb.WG.Add(1)
		go func() {
			defer sb.WG.Done()
			for {
				ipConn, err := sb.TCPDial.Dial("tcp", sb.IpAddress)
				if err != nil {
					sb.BitchLog("tcp connect fail %s", err.Error())
					continue
				}
				conn := tls.Client(ipConn, sb.TLSConfig)
				conn.SetDeadline(time.Now().Add(time.Duration(sb.TCPRWTimeout) * time.Millisecond))
				// Handshake with TLS to get cert
				hsErr := conn.Handshake()
				if hsErr != nil {
					sb.BitchLog("handshake fail %s", hsErr.Error())
					conn.Close()
					continue
				}
				state := conn.ConnectionState()
				if state.HandshakeComplete {
					sb.BitchLog("Version:%v HandshakeComplete:%v DidResume:%v CipherSuite:%x NegotiatedProtocol:%v NegotiatedProtocolIsMutual:%v ServerName:%v CSPResponse:%v", state.Version, state.HandshakeComplete, state.DidResume, state.CipherSuite, state.NegotiatedProtocol, state.NegotiatedProtocolIsMutual, state.ServerName, string(state.OCSPResponse))
				} else {
					sb.BitchLog("handshake failure")
				}
				conn.Close()
			}
		}()
	}
	sb.WG.Wait()
}

func (sb *SSLBitch) BenchMark_HTTPS() {
	if !sb.Https || sb.OnlyHandShake || sb.ScanCipher {
		return
	}
	strUrl := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s", sb.ReqUrl, sb.DomainName)

	if sb.KeepAlive {
		strUrl = fmt.Sprintf("%s\r\nConnection: Keep-Alive", strUrl)
	}
	strUrl = fmt.Sprintf("%s\r\n%s", strUrl, strings.Join(sb.Headers, "\r\n"))
	strUrl = fmt.Sprintf("%s\r\n\r\n", strUrl)
	fmt.Println(strUrl)
	for count := 1; count <= sb.Conncurency; count++ {
		sb.WG.Add(1)
		go func() {
			defer sb.WG.Done()
			var ipConn net.Conn
			var tcperr error
			var conn *tls.Conn
			buf := make([]byte, sb.ReadBuffer)
			for {
			RETRY:
				//prepare for tcp connection
				ipConn, tcperr = sb.TCPDial.Dial("tcp", sb.IpAddress)
				if tcperr != nil {
					sb.BitchLog("tcp connect fail %s", tcperr.Error())
					continue
				}
				//prepare for tls connection
				conn = tls.Client(ipConn, sb.TLSConfig)
				//print handshake detail
				/*hsEerr :=conn.Handshake()
				if hsEerr != nil{
					sb.BitchLog("handshake failed,%s",hsEerr)
					conn.Close()
					continue
				}
				cstate := conn.ConnectionState()
				sb.BitchLog("%+v",cstate)*/

				if !sb.KeepAlive {
					_, werr := conn.Write([]byte(strUrl))
					if werr != nil {
						conn.Close()
						ipConn.Close()
						conn = nil
						ipConn = nil
						goto RETRY
					}
					_, rerr := conn.Read(buf)
					if rerr != nil {
						conn.Close()
						ipConn.Close()
						conn = nil
						ipConn = nil
						goto RETRY
					}
					sb.BitchLog("%s", buf)
					_ = buf
					conn.Close()
					goto RETRY
				} else {
					for {
						buf := make([]byte, 1024)
						_, werr := conn.Write([]byte(strUrl))
						if werr != nil {
							break
						}
						_, rerr := conn.Read(buf)
						_ = buf
						if rerr != nil {
							break
						}
					}
				}
			}

		}()
	}
	sb.WG.Wait()
}

func (sb *SSLBitch) BenchMark_HTTP() {

	if sb.Https || sb.ScanCipher || sb.OnlyHandShake {
		return
	}
	strUrl := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s", sb.ReqUrl, sb.DomainName)
	if sb.KeepAlive {
		strUrl = fmt.Sprintf("%s\r\nConnection: Keep-Alive", strUrl)
	}
	strUrl = fmt.Sprintf("%s\r\n%s", strUrl, strings.Join(sb.Headers, "\r\n"))
	strUrl = fmt.Sprintf("%s\r\n\r\n", strUrl)
	fmt.Println(strUrl)
	for count := 1; count <= sb.Conncurency; count++ {
		sb.WG.Add(1)
		go func() {
			defer sb.WG.Done()
			var innerWG sync.WaitGroup
			for {
				//prepare for tcp connection
				conn, err := sb.TCPDial.Dial("tcp", sb.IpAddress)
				if err != nil {
					sb.BitchLog("tcp connect fail %s", err.Error())
					continue
				}
				//set tcp read write timeoute
				conn.SetWriteDeadline(time.Now().Add(time.Duration(sb.TCPRWTimeout) * time.Second))

				//read from server
				innerWG.Add(1)
				buf := make([]byte, 1024)

				for {

					sb.BitchLog("bef write")
					_, werr := conn.Write([]byte(strUrl))
					sb.BitchLog("aft write")
					if werr != nil {
						sb.BitchLog("write %s", werr.Error())
						break
					}

					sb.BitchLog("bef read")
					_, rerr := conn.Read(buf)
					sb.BitchLog("aft read")
					if rerr != nil {
						sb.BitchLog("write %s", rerr.Error())
						break
					}
					sb.BitchLog("%s", buf)

				}
			}
		}()
	}
	sb.WG.Wait()
}

func (sb *SSLBitch) Scan_Ciphers() {
	if !sb.Https || sb.OnlyHandShake {
		return
	}
	var tmpcipher []uint16
	if sb.ScanCipher {
		for _, h := range sb.DefaultCiphers {
			ipConn, err := sb.TCPDial.Dial("tcp", sb.IpAddress)
			if err != nil {
				sb.BitchLog("tcp connect fail ", err.Error())
				continue
			}
			//prepare for tls connection
			conn := tls.Client(ipConn, sb.TLSConfig)
			//set tcp read and write timeout
			conn.SetDeadline(time.Now().Add(time.Duration(sb.TCPRWTimeout) * time.Second))
			sb.TLSConfig.CipherSuites = []uint16{h}
			if hsErr := conn.Handshake(); hsErr != nil {
				sb.BitchLog("%x,%s", h, hsErr.Error())
				conn.Close()
				continue
			} else {
				stat := conn.ConnectionState()
				if stat.HandshakeComplete {
					sb.BitchLog("%x,%x,%s", stat.Version, h, "yes")
					tmpcipher = append(tmpcipher, h)
					conn.Close()
					continue
				}
			}
		}
	}
}

//TODO
//publish and deliver with channnel
func (sb *SSLBitch) BitchLog(format string, a ...interface{}) {
	if sb.Verbose {
		fmt.Printf(format+"\n", a...)
	}
}
