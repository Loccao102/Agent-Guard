package adapters
import("strings";"testing")
func TestRenderClaude(t *testing.T){got,err:=Render(Options{Agent:"claude",Name:"demo",Executable:"demo-server",Args:[]string{"--stdio"}});if err!=nil{t.Fatal(err)};if !strings.Contains(got,"claude mcp add")||!strings.Contains(got,"agentguard mcp proxy"){t.Fatal(got)}}
