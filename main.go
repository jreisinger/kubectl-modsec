package main

import (
	"log"
	"os"

	"github.com/jreisinger/kubectl-modsec/cmd"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "modsec",
		Usage: "extract ModSecurity WAF information from Kubernetes",
		Commands: []*cli.Command{
			&cmd.Ingresses,
			&cmd.Logs,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
