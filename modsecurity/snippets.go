package modsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	networkingV1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func ExplainModsecurityIngress() string {
	explanation := `Modsecurity and Ingress

Modsecurity is Web Application Firewall engine that can protect HTTP
applications against some attacks. It's implemented in the form of a module
(library) for a web server like Apache or Nginx. Thus it's possible to use it
from Nginx Ingress controller. 

Nginx Ingress is configured via a ConfigMap used by ingress controller pods to
set global options. Particular ingresses can be configured via annotations like:

nginx.ingress.kubernetes.io/modsecurity-snippet: |
SecRuleEngine On
SecDebugLog /tmp/modsec_debug.log
`
	return explanation
}

type Ingress struct {
	Namespace     string
	Ingress       string
	ModsecSnippet []string
	Rules         []Rule
}

type Rule struct {
	Host  string
	Paths []string
}

func newIngress(in networkingV1.Ingress) Ingress {
	var rules []Rule
	for _, rule := range in.Spec.Rules {
		var paths []string
		for _, path := range rule.HTTP.Paths {
			paths = append(paths, path.Path)
		}
		rule := Rule{
			Host:  rule.Host,
			Paths: paths,
		}
		rules = append(rules, rule)
	}

	var modsecsnippet []string
	for k, v := range in.Annotations {
		if isModsecSnippet(k) {
			for _, line := range strings.Split(v, "\n") {
				cleanline := strings.TrimSpace(line)
				if cleanline != "" && !strings.HasPrefix(cleanline, "#") {
					modsecsnippet = append(modsecsnippet, cleanline)
				}
			}
		}
	}

	return Ingress{
		Namespace:     in.ObjectMeta.Namespace,
		Ingress:       in.ObjectMeta.Name,
		Rules:         rules,
		ModsecSnippet: modsecsnippet,
	}
}

func isModsecSnippet(v string) bool {
	return v == "nginx.ingress.kubernetes.io/modsecurity-snippet"
}

type Ingresses []Ingress

func newIngresses(in []networkingV1.Ingress) Ingresses {
	var ingresses Ingresses
	for _, i := range in {
		ingresses = append(ingresses, newIngress(i))
	}
	return ingresses
}

func GetIngresses(cs *kubernetes.Clientset, host string) (Ingresses, error) {
	ii := cs.NetworkingV1().Ingresses("")
	il, err := ii.List(context.TODO(), v1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return newIngresses(il.Items), nil
}

func (ings Ingresses) StringJson() string {
	b, err := json.Marshal(ings)
	if err != nil {
		return ""
	}
	return string(b)
}

func (ings Ingresses) StringTable() string {
	var out bytes.Buffer

	const format = "%v\t%v\t%v\n"

	tw := new(tabwriter.Writer).Init(&out, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, format, "Namespace", "Ingress", "ModsecSnippet")
	fmt.Fprintf(tw, format, "---------", "-------", "-------------")

	for _, ing := range ings {
		for i := range ing.ModsecSnippet {
			ing.ModsecSnippet[i] = truncate(ing.ModsecSnippet[i], 70)
		}
		fmt.Fprintf(tw, format, ing.Namespace, ing.Ingress, strings.Join(ing.ModsecSnippet, ";"))
	}

	tw.Flush()
	return out.String()
}
