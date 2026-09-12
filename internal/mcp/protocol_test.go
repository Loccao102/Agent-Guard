package mcp

import("strings";"testing")
func TestParseToolCall(t *testing.T){line:=[]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_items","arguments":{"limit":2}}}`);msg,call,ok:=ParseToolCall(line);if !ok||call.Name!="list_items"||string(msg.ID)!="7"{t.Fatalf("unexpected parse: %#v %#v %v",msg,call,ok)};value:=ActionValue("demo",call);if !strings.Contains(value,"demo/list_items"){t.Fatal(value)}}
