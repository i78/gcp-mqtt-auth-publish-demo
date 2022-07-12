package mqtt

type Config struct {
	Broker               string
	ClientId             string
	Topic                string
	ClientCertificate    string
	ClientKey            string
	TrustedCACertificate string
}
