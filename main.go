package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/pleme-io/terraform-provider-opadmin/internal/provider"
)

var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.opentofu.org/pleme-io/opadmin",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
