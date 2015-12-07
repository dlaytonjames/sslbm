package main

	//https://www.ssllabs.com/ssltest/viewMyClient.html
	//http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
	//https://testssl.sh/openssl-rfc.mappping.html

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
	"strings"
	"runtime/pprof"
)

func Usage() {
	flag.PrintDefaults()
	fmt.Println(`
REPORTING BUGS
       hewenqian@xiaomi.com
`)
}

func main() {
	defer func() {
		if x := recover(); x != nil {
			fmt.Printf("%v", x)
		}
	}()



	sslbitch := new(SSLBitch)
	cipher := new(Ciphers)
	//var headers HeaderSlice
	flag.Var(&sslbitch.Headers ,"header","request header")
	flag.StringVar(&sslbitch.IpAddress, "ip", "", "IP Address")
	flag.StringVar(&sslbitch.DomainName, "domain", "", "Domain Name")
	flag.StringVar(&sslbitch.Port, "port", "443", "Port Number")
	flag.StringVar(&sslbitch.ReqUrl, "uri", "/index.html", "request uri")
	flag.StringVar(&sslbitch.Reqcipher, "cipher", "cipher1:cipher2:cipher3", "ciphersuite see ciphers(1)")
	flag.StringVar(&sslbitch.PproFileLog,"profilelog","/tmp/cpuprofile.prof","profile path")
	flag.IntVar(&sslbitch.Conncurency, "client", 500, "concurrency")
	flag.BoolVar(&sslbitch.Insecure, "InsecureSkipVerify", true, "Allow connections to SSL sites without certs (H)")
	flag.BoolVar(&sslbitch.PreferServerSuites, "preferServerSuite", true, "Prefer Server side Cipher Suites")
	flag.BoolVar(&sslbitch.OnlyHandShake, "onlyHandShake", false, "get data from server, only do https handshake when false")
	flag.IntVar(&sslbitch.TCPRWTimeout, "rwTimeout", 20, "sets the read and write deadlines associated with the connection.  ms")
	flag.IntVar(&sslbitch.DialTimeout, "tcpTimeout", 1, "tcp connect timeout 1 ms")
	flag.IntVar(&sslbitch.Duration, "duration", 10, "duration to benchmark default 10s")
	flag.IntVar(&sslbitch.KeepAliveTimeOUt, "ktt", 0, "tcp keepalive timeout 0 ms")
	flag.IntVar(&sslbitch.SessionCacheCapacity,"sessionCacheCapacity",20480,"session cache capacity")
	flag.IntVar(&sslbitch.ReadBuffer,"readBuffer",2048,"response read buffer")
	flag.IntVar(&sslbitch.CpuNum,"boom",runtime.NumCPU(),"burn cpu")
	flag.BoolVar(&sslbitch.SessionTicket, "sessionTicketDisabled", true, "SessionTicketsDisabled may be set to true to disable session ticket(resumption) support.")
	flag.BoolVar(&sslbitch.SessionCache,"sessionCache",false,"session cache ")
	flag.BoolVar(&sslbitch.KeepAlive, "keepAlive", false, "keep-alive")
	flag.BoolVar(&sslbitch.Verbose, "verbose", false, "verbose")
	flag.BoolVar(&sslbitch.ScanCipher, "scancipher", false, "scan ciphers")
	flag.BoolVar(&sslbitch.Https, "https", true, "schme")
	flag.BoolVar(&sslbitch.Pprofile,"pprofile",false,"CPU pprof")
	flag.Parse()
	runtime.GOMAXPROCS(sslbitch.CpuNum)
	sslbitch.BitchLog("%s\n","Request headers")
	sslbitch.BitchLog("%s\n",strings.Join(sslbitch.Headers,"\r\n"))

	//profile
	if sslbitch.Pprofile{
		f, err := os.Create(sslbitch.PproFileLog)
		if err != nil {
		os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	///parameter check
	if sslbitch.IpAddress == "" {
		if sslbitch.DomainName == "" {
			fmt.Println("missing parameters!")
			Usage()
			os.Exit(1)
		}
		//TODO
		//lookup up domain ,benmark all ip.
		ip, err := net.LookupHost(sslbitch.DomainName)
		if err != nil {
			fmt.Printf("Could not resolve domain name, %v.\n\n", sslbitch.DomainName)
			os.Exit(1)
		}
		sslbitch.IpAddress = ip[0] + ":" + sslbitch.Port
	} else {
		sslbitch.IpAddress = sslbitch.IpAddress + ":" + sslbitch.Port
	}
	// default cipher
	cipher.CipherMap = map[string]uint16{
		"RC4-SHA":0x0005,
		"DES-CBC3-SHA":0x000a,
		"AES128-SHA":0x002f,
		"AES256-SHA":0x0035,
		"TLS_FALLBACK_SCSV":0x5600,
		"ECDHE-ECDSA-RC4-SHA":0xc007,
		"ECDHE-ECDSA-AES128-SHA":0xc009,
		"ECDHE-ECDSA-AES256-SHA":0xc00a,
		"ECDHE-RSA-RC4-SHA":0xc011,
		"ECDHE-RSA-DES-CBC3-SHA":0xc012,
		"ECDHE-RSA-AES128-SHA":0xc013,
		"ECDHE-RSA-AES256-SHA":0xc014,
		"ECDHE-ECDSA-AES128-GCM-SHA256":0xc02b,
		"ECDHE-ECDSA-AES256-GCM-SHA384":0xc02c,
		"ECDHE-RSA-AES128-GCM-SHA256":0xc02f,
		"ECDHE-RSA-AES256-GCM-SHA384":0xc030,
	}

	//prepare Tls config
	tlsconfig := &tls.Config{
		ServerName:               sslbitch.DomainName,
		InsecureSkipVerify:       sslbitch.Insecure,
		PreferServerCipherSuites: sslbitch.PreferServerSuites,
		SessionTicketsDisabled: sslbitch.SessionTicket,
		ClientSessionCache: tls.NewLRUClientSessionCache(sslbitch.SessionCacheCapacity),
		CipherSuites: nil,

	}
	//prepare net config
	netDial := &net.Dialer{
		Timeout: time.Duration(sslbitch.DialTimeout) * time.Millisecond,
		KeepAlive: time.Millisecond*time.Duration(sslbitch.KeepAliveTimeOUt),
	}
	sslbitch.TLSConfig = tlsconfig
	sslbitch.TCPDial = netDial

	if sslbitch.Reqcipher != "cipher1:cipher2:cipher3"{
		ci := make([]string,100)
		if strings.Contains(sslbitch.Reqcipher, ":"){
			 ci = strings.Split(sslbitch.Reqcipher, ":")
		}else{
			ci[0] = sslbitch.Reqcipher
		}
		css ,err := cipher.ciphers(ci)
		if err !=nil && !sslbitch.ScanCipher{
			fmt.Printf("set ciphersuites failed! %s ,%s",err.Error(),sslbitch.ScanCipher)
			os.Exit(1)
		}else{
				sslbitch.TLSConfig.CipherSuites = css
		}
		if sslbitch.ScanCipher{
			sslbitch.DefaultCiphers = []uint16{
				0xC030,	0xC02F,	0xC02C,	0xC02B,
				0xC014,	0xC013,	0xC012,	0xC00A,
				0xC009,	0x5600,	0x0035,	0x002F,
				0x000A,	0x0005,	0xC007,	0xC011,
			}
		}
	}
	//TODO
	//change for time.Ticker
	if sslbitch.ScanCipher{
		fmt.Println("start Scan Ciphers")
		go sslbitch.Scan_Ciphers()
		time.Sleep(time.Second*time.Duration(sslbitch.Duration))
		os.Exit(0)
	}
	if sslbitch.OnlyHandShake {
		fmt.Println("start handshake benchmarking")
		go sslbitch.BenchMark_HandShake()
		time.Sleep(time.Second*time.Duration(sslbitch.Duration))
		os.Exit(0)
	}
	if sslbitch.Https{
		fmt.Println("start https benchmarking")
		go sslbitch.BenchMark_HTTPS()
		time.Sleep(time.Second*time.Duration(sslbitch.Duration))
		os.Exit(0)
	}else{
		fmt.Println("start http benchmarking")
		go sslbitch.BenchMark_HTTP()
		time.Sleep(time.Second*time.Duration(sslbitch.Duration))
		os.Exit(0)
	}
	fmt.Println("bye!")
}