A kubectl [plugin](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/).

```
$ kubectl modsec
NAME:
   modsec - extract Modsecurity related information from Kubernetes

USAGE:
   modsec [global options] command [command options] [arguments...]

COMMANDS:
   snippets  modsecurity snippets from nginx ingresses
   logs      modsecurity logs from nginx ingress controllers
   help, h   Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help (default: false)
```

Installation:

```
$ go install
```
