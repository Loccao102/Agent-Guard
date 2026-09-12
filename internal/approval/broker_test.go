package approval

import("context";"testing";"time")
func TestApproveAndRemember(t *testing.T){b:=New(time.Minute);req,err:=b.Create("codex","mcp","github/create_issue {}","high","write","github-write");if err!=nil{t.Fatal(err)};go func(){_=b.Resolve(req.ID,"allow",true)}();res,err:=b.Wait(context.Background(),req.ID);if err!=nil{t.Fatal(err)};if res.Decision!="allow"||!b.HasGrant("codex","mcp","github/create_issue {}"){t.Fatalf("unexpected resolution: %+v",res)}}
func TestRejectInvalidDecision(t *testing.T){b:=New(time.Minute);req,_:=b.Create("a","shell","x","low","reason","rule");if err:=b.Resolve(req.ID,"maybe",false);err==nil{t.Fatal("expected error")}}
