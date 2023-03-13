package cmd

import (
	"fmt"

	"github.com/jreisinger/kubectl-modsec/api"
	"github.com/jreisinger/kubectl-modsec/modsecurity"
	"github.com/urfave/cli/v2"
)

var Logs = cli.Command{
	Name:  "logs",
	Usage: "modsecurity logs from nginx ingress controllers",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "json",
			Usage: "JSON output with modsecurity message details",
		},
		&cli.IntFlag{
			Name:  "code",
			Usage: "only logs with the HTTP response code",
		},
		&cli.IntFlag{
			Name:  "maxuri",
			Value: 30,
			Usage: "truncate URI in table output to this length",
		},
	},
	Action: func(cCtx *cli.Context) error {
		clientset, err := api.GetClientset()
		if err != nil {
			return err
		}

		logs, err := modsecurity.GetLogs(clientset, cCtx.Int("code"))
		if err != nil {
			return err
		}
		if cCtx.Bool("json") {
			fmt.Print(logs.StringJson())
		} else {
			fmt.Print(logs.StringTable(cCtx.Int("maxuri")))
		}

		return nil
	},
}
