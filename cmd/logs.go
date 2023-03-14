package cmd

import (
	"fmt"
	"time"

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
		&cli.DurationFlag{
			Name:  "since",
			Value: time.Hour * 24,
			Usage: "only logs newer than a relative duration like 5s, 2m, or 3h",
		},
		&cli.IntFlag{
			Name:  "code",
			Usage: "only logs with the HTTP response code",
		},
		&cli.StringFlag{
			Name:    "selector",
			Aliases: []string{"l"},
			Value:   "app=ingress-nginx-controller",
			Usage:   "label selector",
		},
	},
	Action: func(cCtx *cli.Context) error {
		clientset, err := api.GetClientset()
		if err != nil {
			return err
		}

		logs, err := modsecurity.GetLogs(clientset, cCtx.String("selector"), cCtx.Duration("since"), cCtx.Int("code"))
		if err != nil {
			return err
		}
		if cCtx.Bool("json") {
			fmt.Print(logs.StringJson())
		} else {
			fmt.Print(logs.StringTable())
		}

		return nil
	},
}
