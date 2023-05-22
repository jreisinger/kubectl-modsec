Kubectl-modsec extracts information about [ModSecurity WAF](https://kubernetes.github.io/ingress-nginx/user-guide/third-party-addons/modsecurity/) from Kubernetes.

```
$ kubectl-modsec
NAME:
   modsec - extract ModSecurity WAF information from Kubernetes

USAGE:
   modsec [global options] command [command options] [arguments...]

COMMANDS:
   ingresses, ing  relevant info on nginx ingresses
   logs            modsecurity logs from nginx ingress controllers
   help, h         Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help (default: false)
```

It can be used as a [kubectl plugin](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/).

```
$ kubectl modsec logs -since 10m
Timestamp            Host         Client IP      Method  URI                         Code  Secrules       Rule IDs
---------            ----         --------       ------  ---                         ----  --------       --------
2023-03-13_12:56:01  example.net  93.155.154.11  GET     /somepath?page=/etc/passwd  403   Enabled        930120 932160 949110
2023-03-13_12:49:05  52.2.86.102  46.120.102.57  GET     /.env                       404   DetectionOnly  930130 949110
```

Installation:

```
$ go install
```
