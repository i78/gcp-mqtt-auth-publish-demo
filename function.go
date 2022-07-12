// Package p contains an HTTP Cloud Function.
package p

import (
	"example.com/cloudfunction/mqtt"
	"math/rand"
	"net/http"
	"time"
)

func EmitFakeData(w http.ResponseWriter, r *http.Request) {

	emitter := mqtt.NewMQTTEmitter(mqtt.Config{
		Broker:   "ssl://mqtt.googleapis.com:8883",
		ClientId: "projects/$(PROJECT_NAME)/locations/europe-west1/registries/test/devices/test"
		Topic:    "/devices/test/events",
		// TODO: The certificates should be stored in a secret when not used for local testing
		ClientCertificate:    "serverless_function_source_code/config/client.crt",
		ClientKey:            "serverless_function_source_code/config/client.pem",
		TrustedCACertificate: "serverless_function_source_code/config/ca-crt.key",
	})

	for {
		dummy := 20.0 + (10 * rand.Float32())
		emitter.EmitNewSample(time.Now(), dummy)
		time.Sleep(1000 * time.Millisecond)
	}
}
