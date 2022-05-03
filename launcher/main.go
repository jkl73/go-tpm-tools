// package main is a program that will start a container with attestation.
package main

import (
	"context"
	"flag"
	"log"
	"os"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm/tpm2"
)

var (
	useLocalImage = flag.Bool("use_local_image", false, "use local image instead of pulling image from the repo, only for testing purpose")
	serverAddr    = flag.String("addr", "", "The server address in the format of host:port")
)

func main() {
	flag.Parse()
	os.Exit(run())
}

func run() int {
	logger := log.Default()
	logger.Println("TEE container launcher starting...")

	mdsClient := metadata.NewClient(nil)
	ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)
	projectID, err := mdsClient.ProjectID()
	if err != nil {
		logger.Printf("cannot get projectID, not in GCE? %v", err)
		return 1
	}
	logClient, err := logging.NewClient(context.Background(), projectID)
	if err != nil {
		logger.Printf("cannot setup Cloud Logging, using the default logger %v", err)
	} else {
		defer logClient.Close()
		logger.Println("logs will publish to Cloud Logging")
		logger = logClient.Logger("confidential-space-launcher").StandardLogger(logging.Info)
	}

	spec, err := spec.GetLauncherSpec(mdsClient)
	if err != nil {
		logger.Println(err)
		return 1
	}

	spec.UseLocalImage = *useLocalImage
	spec.AttestationServiceAddr = *serverAddr
	logger.Println("Launcher Spec: ", spec)

	client, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		logger.Println(err)
		return 1
	}
	defer client.Close()

	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		logger.Println(err)
		return 1
	}
	defer tpm.Close()

	token, err := RetrieveAuthToken(mdsClient)
	if err != nil {
		logger.Printf("failed to retrieve auth token: %v, using empty auth", err)
	}

	r, err := NewRunner(ctx, client, token, spec, mdsClient, tpm, logger)
	if err != nil {
		logger.Println(err)
		return 1
	}
	defer r.Close(ctx)

	if err := r.Run(ctx); err != nil {
		logger.Println(err)
		return 1
	}
	return 0
}
