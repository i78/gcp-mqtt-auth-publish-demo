package mqtt

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	MQTT "github.com/eclipse/paho.mqtt.golang"
	jwt "github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"time"
)

// MQTTEmitter implements the Emitter Interface towards an MQTT client
type MQTTEmitter struct {
	client MQTT.Client
	config Config
}

func NewMQTTEmitter(cfg Config) (e *MQTTEmitter) {
	// inspired by
	// https://github.com/eclipse/paho.mqtt.golang/blob/master/cmd/ssl/main.go
	certpool := x509.NewCertPool()
	pemCerts, err := ioutil.ReadFile(cfg.TrustedCACertificate)
	if err == nil {
		certpool.AppendCertsFromPEM(pemCerts)
	}

	// Import client certificate/key pair
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertificate, cfg.ClientKey)
	if err != nil {
		panic(err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic(err)
	}
	fmt.Println(cert.Leaf.DNSNames)

	tlsConfig := tls.Config{
		// RootCAs = certs used to verify server cert.
		RootCAs: certpool,
		// ClientAuth = whether to request cert from server.
		// Since the server is set up for SSL, this happens
		// anyways.
		ClientAuth: tls.NoClientCert,
		// ClientCAs = certs used to validate client cert.
		ClientCAs: nil,
		// InsecureSkipVerify = verify that cert contents
		// match server. IP matches what is in cert etc.
		// You might want to set this to false for production. :)
		InsecureSkipVerify: true,
		// Certificates = list of certs client sends to server.
		Certificates: []tls.Certificate{cert},
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = jwt.StandardClaims{
		Audience:  "$(PROJECT_NAME)",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}

	log.Println("[main] Load Private Key")
	keyBytes, err := ioutil.ReadFile(cfg.ClientKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("[main] Parse Private Key")
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("[main] Sign String")
	tokenString, err := token.SignedString(key)
	if err != nil {
		log.Fatal(err)
	}

	opts := MQTT.NewClientOptions().
		AddBroker(cfg.Broker).
		SetTLSConfig(&tlsConfig).
		SetProtocolVersion(4).
		SetClientID(cfg.ClientId).
		SetUsername("unused").
		SetPassword(tokenString)

	client := MQTT.NewClient(opts)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	return &MQTTEmitter{client: client, config: cfg}
}

func (e *MQTTEmitter) EmitNewSample(sampletime time.Time, nextStatus float32) {

	type FullStatus struct {
		SampleTime  time.Time `json:"sample_time"`
		Temperature float32   `json:"temperature"`
	}

	demoJson := &FullStatus{SampleTime: sampletime, Temperature: nextStatus}
	payloadJson, _ := json.Marshal(demoJson)
	payloadString := string(payloadJson)

	log.WithFields(log.Fields{
		"sampletime": sampletime,
		"value":      payloadJson,
		"payload":    payloadString,
	}).Info("Emitting new Status")

	e.client.Publish(e.config.Topic, 0, true, payloadString)

}
