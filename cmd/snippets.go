package cmd

import (
	"fmt"

	"github.com/jreisinger/kubectl-modsec/api"
	"github.com/jreisinger/kubectl-modsec/modsecurity"
	"github.com/urfave/cli/v2"
)

var Snippets = cli.Command{
	Name:  "snippets",
	Usage: "modsecurity snippets from nginx ingresses",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "json",
			Usage: "JSON output",
		},
		&cli.BoolFlag{
			Name:  "explain",
			Usage: "explain modsecurity and ingress",
		},
	},
	Action: func(cCtx *cli.Context) error {
		if cCtx.Bool("explain") {
			fmt.Print(modsecurity.ExplainModsecurityIngress())
			return nil
		}

		clientset, err := api.GetClientset()
		if err != nil {
			return err
		}

		ingresses, err := modsecurity.GetIngresses(clientset)
		if err != nil {
			return err
		}
		if cCtx.Bool("json") {
			fmt.Print(ingresses.StringJson())
		} else {
			fmt.Print(ingresses.StringTable())
		}

		return nil
	},
}
