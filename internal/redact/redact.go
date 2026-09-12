package redact

import "regexp"

type Redactor struct{patterns []*regexp.Regexp}
func New() Redactor{raw:=[]string{`(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+\-/=]+`,`(?i)((?:api[_-]?key|token|secret|password)\s*[=:]\s*)[^\s,;]+`,`(?i)(github_pat_)[A-Za-z0-9_]+`,`(?i)(sk-[A-Za-z0-9_-]{12,})`};out:=Redactor{};for _,p:=range raw{out.patterns=append(out.patterns,regexp.MustCompile(p))};return out}
func(r Redactor)String(v string)string{for _,re:=range r.patterns{v=re.ReplaceAllStringFunc(v,func(s string)string{m:=re.FindStringSubmatch(s);if len(m)>1&&m[1]!=""{return m[1]+"[REDACTED]"};return "[REDACTED]"})};return v}
