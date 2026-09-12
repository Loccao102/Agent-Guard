package main

import(
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
	"github.com/Loccao102/Agent-Guard/internal/adapters"
	"github.com/Loccao102/Agent-Guard/internal/approval"
	"github.com/Loccao102/Agent-Guard/internal/audit"
	"github.com/Loccao102/Agent-Guard/internal/config"
	"github.com/Loccao102/Agent-Guard/internal/guard"
	"github.com/Loccao102/Agent-Guard/internal/mcp"
	"github.com/Loccao102/Agent-Guard/internal/packs"
	"github.com/Loccao102/Agent-Guard/internal/policy"
	"github.com/Loccao102/Agent-Guard/internal/risk"
	"github.com/Loccao102/Agent-Guard/internal/server"
	"github.com/Loccao102/Agent-Guard/internal/signing"
)
var version="1.0.0"
func main(){if len(os.Args)<2{usage();os.Exit(2)};var err error;switch os.Args[1]{case"init":err=initCommand(os.Args[2:]);case"run":err=runCommand(os.Args[2:]);case"check":err=checkCommand(os.Args[2:]);case"mcp":err=mcpCommand(os.Args[2:]);case"adapter":err=adapterCommand(os.Args[2:]);case"pack":err=packCommand(os.Args[2:]);case"keygen":err=keygenCommand(os.Args[2:]);case"sign":err=signCommand(os.Args[2:]);case"verify":err=verifyCommand(os.Args[2:]);case"audit":err=auditCommand(os.Args[2:]);case"version","--version","-v":fmt.Println("AgentGuard",version);return;default:usage();os.Exit(2)};if err!=nil{log.Fatal(err)}}
func usage(){fmt.Println(`AgentGuard - local-first firewall for AI agents

Usage:
  agentguard init [--force]
  agentguard run [--config agentguard.yaml]
  agentguard check --kind shell --value "git push origin main"
  agentguard mcp proxy --agent codex --server demo -- <server> [args...]
  agentguard adapter <codex|claude|gemini> --name demo -- <server> [args...]
  agentguard pack install --pack policies/safe-dev.yaml
  agentguard keygen [--private publisher.key] [--public publisher.pub]
  agentguard sign --file PACK --private-key KEY
  agentguard verify --file PACK --public-key KEY
  agentguard audit verify [--config agentguard.yaml]
  agentguard version`)}
func initCommand(args []string)error{fs:=flag.NewFlagSet("init",flag.ContinueOnError);force:=fs.Bool("force",false,"overwrite an existing config");path:=fs.String("config","agentguard.yaml","config path");if err:=fs.Parse(args);err!=nil{return err};if !*force{if _,err:=os.Stat(*path);err==nil{return fmt.Errorf("%s already exists (use --force to overwrite)",*path)}};if err:=os.WriteFile(*path,[]byte(config.DefaultYAML),0o644);err!=nil{return err};fmt.Printf("created %s\n",*path);return nil}
func runCommand(args []string)error{fs:=flag.NewFlagSet("run",flag.ContinueOnError);path:=fs.String("config","agentguard.yaml","config path");if err:=fs.Parse(args);err!=nil{return err};cfg,engine,store,err:=loadRuntime(*path);if err!=nil{return err};defer store.Close();broker:=approval.New(2*time.Minute);g:=guard.New(engine,risk.NewAnalyzer(),store,broker);srv:=server.New(cfg.Server,g,store);log.Printf("AgentGuard v%s dashboard: http://%s:%d",version,cfg.Server.Host,cfg.Server.Port);return srv.ListenAndServe()}
func checkCommand(args []string)error{fs:=flag.NewFlagSet("check",flag.ContinueOnError);path:=fs.String("config","agentguard.yaml","config path");kind:=fs.String("kind","","action kind");value:=fs.String("value","","action value");agent:=fs.String("agent","cli","agent name");if err:=fs.Parse(args);err!=nil{return err};if *kind==""||*value==""{return fmt.Errorf("--kind and --value are required")};cfg,err:=config.Load(*path);if err!=nil{return err};engine,err:=policy.NewEngine(cfg.Default,cfg.Rules);if err!=nil{return err};decision:=engine.Evaluate(*kind,*value);rr:=risk.NewAnalyzer().Analyze(*kind,*value);out:=map[string]any{"agent":*agent,"kind":*kind,"value":*value,"decision":decision.Decision,"rule_id":decision.RuleID,"reason":decision.Reason,"risk":rr.Level,"risk_reasons":rr.Reasons};enc:=json.NewEncoder(os.Stdout);enc.SetIndent("","  ");return enc.Encode(out)}
func mcpCommand(args []string)error{if len(args)==0||args[0]!="proxy"{return fmt.Errorf("usage: agentguard mcp proxy [flags] -- <server> [args...]")};fs:=flag.NewFlagSet("mcp proxy",flag.ContinueOnError);endpoint:=fs.String("endpoint","http://127.0.0.1:7788","AgentGuard endpoint");agent:=fs.String("agent","mcp-client","calling agent");serverName:=fs.String("server","server","MCP server alias");if err:=fs.Parse(args[1:]);err!=nil{return err};cmdArgs:=fs.Args();if len(cmdArgs)==0{return fmt.Errorf("downstream MCP command required after --")};return mcp.Run(context.Background(),mcp.RunnerOptions{Endpoint:*endpoint,Agent:*agent,ServerName:*serverName,Command:cmdArgs[0],Args:cmdArgs[1:]})}
func adapterCommand(args []string)error{if len(args)==0{return fmt.Errorf("adapter name required: codex, claude, or gemini")};agent:=args[0];fs:=flag.NewFlagSet("adapter "+agent,flag.ContinueOnError);name:=fs.String("name","","MCP server name");endpoint:=fs.String("endpoint","http://127.0.0.1:7788","AgentGuard endpoint");if err:=fs.Parse(args[1:]);err!=nil{return err};cmdArgs:=fs.Args();if *name==""||len(cmdArgs)==0{return fmt.Errorf("--name and downstream command after -- are required")};out,err:=adapters.Render(adapters.Options{Agent:agent,Name:*name,Endpoint:*endpoint,Executable:cmdArgs[0],Args:cmdArgs[1:]});if err!=nil{return err};fmt.Println(out);return nil}
func packCommand(args []string)error{if len(args)==0||args[0]!="install"{return fmt.Errorf("usage: agentguard pack install --pack FILE")};fs:=flag.NewFlagSet("pack install",flag.ContinueOnError);configPath:=fs.String("config","agentguard.yaml","config path");packPath:=fs.String("pack","","policy pack path");pub:=fs.String("public-key","","publisher public key");sig:=fs.String("signature","","pack signature");if err:=fs.Parse(args[1:]);err!=nil{return err};if *packPath==""{return fmt.Errorf("--pack is required")};p,err:=packs.Install(*configPath,*packPath,*pub,*sig);if err!=nil{return err};fmt.Printf("installed policy pack %s@%s (%d rules)\n",p.Name,p.Version,len(p.Rules));return nil}
func keygenCommand(args []string)error{fs:=flag.NewFlagSet("keygen",flag.ContinueOnError);priv:=fs.String("private","publisher.key","private key path");pub:=fs.String("public","publisher.pub","public key path");if err:=fs.Parse(args);err!=nil{return err};if err:=signing.Generate(*priv,*pub);err!=nil{return err};fmt.Printf("created %s and %s\n",*priv,*pub);return nil}
func signCommand(args []string)error{fs:=flag.NewFlagSet("sign",flag.ContinueOnError);file:=fs.String("file","","file to sign");priv:=fs.String("private-key","","Ed25519 private key");sig:=fs.String("signature","","signature output path");if err:=fs.Parse(args);err!=nil{return err};if *file==""||*priv==""{return fmt.Errorf("--file and --private-key are required")};if *sig==""{*sig=*file+".sig"};if err:=signing.SignFile(*file,*priv,*sig);err!=nil{return err};fmt.Printf("signed %s -> %s\n",*file,*sig);return nil}
func verifyCommand(args []string)error{fs:=flag.NewFlagSet("verify",flag.ContinueOnError);file:=fs.String("file","","file to verify");pub:=fs.String("public-key","","Ed25519 public key");sig:=fs.String("signature","","signature path");if err:=fs.Parse(args);err!=nil{return err};if *file==""||*pub==""{return fmt.Errorf("--file and --public-key are required")};if *sig==""{*sig=*file+".sig"};ok,err:=signing.VerifyFile(*file,*pub,*sig);if err!=nil{return err};if !ok{return fmt.Errorf("signature verification failed")};fmt.Println("signature valid");return nil}
func auditCommand(args []string)error{if len(args)==0||args[0]!="verify"{return fmt.Errorf("usage: agentguard audit verify")};fs:=flag.NewFlagSet("audit verify",flag.ContinueOnError);path:=fs.String("config","agentguard.yaml","config path");if err:=fs.Parse(args[1:]);err!=nil{return err};cfg,err:=config.Load(*path);if err!=nil{return err};store,err:=audit.Open(cfg.Audit.Database);if err!=nil{return err};defer store.Close();v,err:=store.Verify();if err!=nil{return err};enc:=json.NewEncoder(os.Stdout);enc.SetIndent("","  ");if err:=enc.Encode(v);err!=nil{return err};if !v.Valid{return fmt.Errorf("audit chain is invalid")};return nil}
func loadRuntime(path string)(config.Config,*policy.Engine,*audit.Store,error){cfg,err:=config.Load(path);if err!=nil{return config.Config{},nil,nil,err};engine,err:=policy.NewEngine(cfg.Default,cfg.Rules);if err!=nil{return config.Config{},nil,nil,err};store,err:=audit.Open(cfg.Audit.Database);if err!=nil{return config.Config{},nil,nil,err};return cfg,engine,store,nil}
