# tlsutil
TLS util functions to help with setting up client &amp; server TLS-based connections.

## Setup
```sh
go get -u github.com/acacio/tlsutil
```


## Use for connection setup
```go
import (
	"github.com/acacio/tlsutil"
)


type Config struct {
	TLSType       string
	VerifyClients bool
	CA            string
	Cert          string
	Key           string
}

func setupServer(cfg *Config) (*tls.Config, error) {
	var tlstype string
	if cfg.VerifyClients {
		tlstype = "verify"
	} else {
		tlstype = "simple"
	}
	// Implicitly requires CA for "verify"
	return tlsutil.SetupServerTLS(tlstype, cfg.CA, cfg.Cert, cfg.Key)
}
```

## TLS combinations

With this library it is possible to setup several different TLS pairings:

| Client \ Server | No srv TLS | Certs<br />`"simple"` | Certs +<br />Client Verification<br />`"verify"`|
| --------------- | :-------: | :-------: | :-------------------------: |
| **No TLS**          | - | N/A       | N/A |
| **Simple TLS**<br />`"simple"`| N/A       | supported | **N/A** |
| **Client Certs**<br />`"certs"` | N/A       | supported | Server enforces Client ID <br /> (server needs CA.crt) |
| **Client Certs +<br />Server Verification**<br />`"verify"`| N/A | Client enforces server ID<br />(client needs CA.crt)| Enforce Client & Server ID<br />(both require CA.crt)|
