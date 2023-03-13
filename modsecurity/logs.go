package modsecurity

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	LabelSelector = "app=ingress-nginx-controller"
)

type Log struct {
	Transaction struct {
		ClientIP  string `json:"client_ip"`
		TimeStamp string `json:"time_stamp"`
		// 	ServerID   string `json:"server_id"`
		// 	ClientPort int    `json:"client_port"`
		// 	HostIP     string `json:"host_ip"`
		// 	HostPort   int    `json:"host_port"`
		// 	UniqueID   string `json:"unique_id"`
		Request struct {
			Method string `json:"method"`
			// 		HTTPVersion float64 `json:"http_version"`
			URI     string `json:"uri"`
			Headers struct {
				// 			UserAgent      string `json:"User-Agent"`
				// 			AcceptCharset  string `json:"Accept-Charset"`
				// 			Authorization  string `json:"Authorization"`
				Host string `json:"Host"`
				// 			CacheControl   string `json:"Cache-Control"`
				// 			Connection     string `json:"Connection"`
				// 			Accept         string `json:"Accept"`
				// 			ContentType    string `json:"Content-Type"`
				// 			ContentLength  string `json:"Content-Length"`
				// 			AcceptEncoding string `json:"Accept-Encoding"`
			} `json:"headers"`
		} `json:"request"`
		Response struct {
			// 		Body     string `json:"body"`
			HTTPCode int `json:"http_code"`
			// 		Headers  struct {
			// 			AccessControlAllowHeaders     string `json:"Access-Control-Allow-Headers"`
			// 			AccessControlAllowMethods     string `json:"Access-Control-Allow-Methods"`
			// 			Date                          string `json:"Date"`
			// 			AccessControlAllowCredentials string `json:"Access-Control-Allow-Credentials"`
			// 			Server                        string `json:"Server"`
			// 			Connection                    string `json:"Connection"`
			// 			AccessControlAllowOrigin      string `json:"Access-Control-Allow-Origin"`
			// 			XContentTypeOptions           string `json:"x-content-type-options"`
			// 			ContentType                   string `json:"Content-Type"`
			// 			ContentLength                 string `json:"Content-Length"`
			// 			AccessControlExposeHeaders    string `json:"Access-Control-Expose-Headers"`
			// 			AccessControlMaxAge           string `json:"Access-Control-Max-Age"`
			// 		} `json:"headers"`
		} `json:"response"`
		Producer struct {
			// 		Modsecurity    string   `json:"modsecurity"`
			// 		Connector      string   `json:"connector"`
			SecrulesEngine string `json:"secrules_engine"`
			// 		Components     []string `json:"components"`
		} `json:"producer"`
		Messages []struct {
			Details struct {
				Accuracy string `json:"accuracy"`
				Data     string `json:"data"`
				// File       string   `json:"file"`
				// LineNumber string   `json:"lineNumber"`
				Match string `json:"match"`
				// Maturity   string   `json:"maturity"`
				// Reference  string   `json:"reference"`
				// Rev        string   `json:"rev"`
				RuleID   string   `json:"ruleId"`
				Severity string   `json:"severity"`
				Tags     []string `json:"tags"`
				Ver      string   `json:"ver"`
			} `json:"details"`
			Message string `json:"message"`
		} `json:"messages"`
	} `json:"transaction"`
}

type Logs []Log

func GetLogs(clientset *kubernetes.Clientset, httpResponseCode int) (Logs, error) {
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(),
		metav1.ListOptions{
			LabelSelector: LabelSelector,
		})
	if err != nil {
		return nil, err
	}

	var logs []Log
	for _, pod := range pods.Items {
		req := clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{})
		podLogs, err := req.Stream(context.TODO())
		if err != nil {
			return nil, err
		}
		defer podLogs.Close()

		line := bufio.NewScanner(podLogs)
		for line.Scan() {
			if isModsecLog(line.Text()) {
				var log Log
				if err := json.Unmarshal(line.Bytes(), &log); err != nil {
					return nil, err
				}
				if httpResponseCode != 0 {
					if log.Transaction.Response.HTTPCode == httpResponseCode {
						logs = append(logs, log)
					}
				} else {
					logs = append(logs, log)
				}
			}
		}
		if line.Err() != nil {
			return nil, line.Err()
		}
	}
	return logs, nil
}

func isModsecLog(line string) bool {
	return strings.HasPrefix(line, `{"transaction":`)
}

func (logs Logs) StringJson() string {
	b, err := json.Marshal(logs)
	if err != nil {
		return ""
	}
	return string(b)
}

func (logs Logs) StringTable() string {
	var out bytes.Buffer

	const format = "%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\n"

	tw := new(tabwriter.Writer).Init(&out, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, format, "Timestamp", "Host", "Client IP", "Method", "URI", "Code", "Secrules", "Rule IDs")

	for _, l := range logs {
		var ruleIDs []string
		for _, m := range l.Transaction.Messages {
			ruleIDs = append(ruleIDs, m.Details.RuleID)
		}
		fmt.Fprintf(tw, format,
			formatTimestamp(l.Transaction.TimeStamp),
			l.Transaction.Request.Headers.Host,
			l.Transaction.ClientIP,
			l.Transaction.Request.Method,
			truncate(l.Transaction.Request.URI, 30),
			l.Transaction.Response.HTTPCode,
			l.Transaction.Producer.SecrulesEngine,
			ruleIDs,
		)
	}

	tw.Flush()
	return out.String()
}

func formatTimestamp(ts string) string {
	// Mon Mar 13 11:02:39 2023
	t, err := time.Parse("Mon Jan 2 15:04:05 2006", ts)
	if err != nil {
		return ts
	}
	return t.Format("2006-01-02_15:04:05")
}

// Truncate truncates s and appends ... if s is longer than max.
func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
