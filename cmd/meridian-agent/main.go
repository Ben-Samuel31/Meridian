package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type target struct { ID string `json:"id"`; Name string `json:"name"`; BaseURL string `json:"base_url"`; Type string `json:"type"`; Schedule int `json:"schedule_interval_seconds"` }
type assertion struct { Field, Rule string `json:"field" json:"rule"`; Value any `json:"value"` }
type probeConfig struct { L1 struct { Timeout int `json:"timeout_ms"` } `json:"l1"`; L2 struct { AuthType string `json:"auth_type"`; TokenEnvVar string `json:"token_env_var"`; HeaderName string `json:"header_name"`; Expected int `json:"expected_status"` } `json:"l2"`; L3 struct { Method string `json:"method"`; Path string `json:"path"`; Query string `json:"query"`; Expected int `json:"expected_status"` } `json:"l3"`; L4 struct { Assertions []assertion `json:"assertions"` } `json:"l4"` }
type assignment struct { Target target `json:"target"`; Config probeConfig `json:"config"` }
type assignmentsResponse struct { Assignments []assignment `json:"assignments"` }
type result struct { Layer int `json:"layer"`; Status string `json:"status"`; Latency int `json:"latency_ms"`; Error string `json:"error_message,omitempty"`; Checked time.Time `json:"checked_at"` }
type submittedRun struct { TargetID string `json:"target_id"`; Started time.Time `json:"started_at"`; Finished time.Time `json:"finished_at"`; Status string `json:"overall_status"`; Results []result `json:"results"` }

func main() {
	api := flag.String("api-url", os.Getenv("MERIDIAN_URL"), "Meridian API URL"); key := flag.String("agent-key", os.Getenv("MERIDIAN_AGENT_KEY"), "Agent enrollment key"); poll := flag.Duration("poll-interval", 10*time.Second, "Assignment polling interval"); flag.Parse()
	if *api=="" || *key=="" { fmt.Fprintln(os.Stderr,"MERIDIAN_URL and MERIDIAN_AGENT_KEY are required"); os.Exit(2) }
	client:=&http.Client{Timeout:30*time.Second}; base:=strings.TrimRight(*api,"/"); last:=map[string]time.Time{}
	for { if err:=heartbeat(client,base,*key);err!=nil{fmt.Fprintln(os.Stderr,"heartbeat:",err)}; assigned,err:=assignments(client,base,*key);if err!=nil{fmt.Fprintln(os.Stderr,"assignments:",err)}else{for _,item:=range assigned{interval:=time.Duration(item.Target.Schedule)*time.Second;if interval<=0||time.Since(last[item.Target.ID])<interval{continue};last[item.Target.ID]=time.Now();run:=execute(item);if err:=submit(client,base,*key,run);err!=nil{fmt.Fprintln(os.Stderr,"submit",item.Target.Name+":",err)}else{fmt.Println("submitted",item.Target.Name,run.Status)}}};time.Sleep(*poll) }
}
func request(client *http.Client, method, endpoint,key string, body []byte)(*http.Response,error){req,err:=http.NewRequest(method,endpoint,bytes.NewReader(body));if err!=nil{return nil,err};req.Header.Set("X-Meridian-Agent-Key",key);if body!=nil{req.Header.Set("Content-Type","application/json")};return client.Do(req)}
func heartbeat(c *http.Client,b,k string)error{r,e:=request(c,"POST",b+"/agent/v1/heartbeat",k,nil);if e!=nil{return e};defer r.Body.Close();if r.StatusCode!=200{return fmt.Errorf("status %d",r.StatusCode)};return nil}
func assignments(c *http.Client,b,k string)([]assignment,error){r,e:=request(c,"GET",b+"/agent/v1/assignments",k,nil);if e!=nil{return nil,e};defer r.Body.Close();if r.StatusCode!=200{return nil,fmt.Errorf("status %d",r.StatusCode)};var out assignmentsResponse;e=json.NewDecoder(r.Body).Decode(&out);if e==nil{fmt.Printf("connected; %d assigned target(s)\n",len(out.Assignments))};return out.Assignments,e}
func submit(c *http.Client,b,k string,run submittedRun)error{body,_:=json.Marshal(run);r,e:=request(c,"POST",b+"/agent/v1/runs",k,body);if e!=nil{return e};defer r.Body.Close();if r.StatusCode!=201{return fmt.Errorf("status %d",r.StatusCode)};return nil}
func execute(item assignment) submittedRun { started:=time.Now().UTC(); results:=[]result{};l1:=connectivity(item.Target,item.Config);results=append(results,l1);if l1.Status=="fail"{return finalize(item.Target.ID,started,results)};l2:=auth(item.Target,item.Config);results=append(results,l2);if l2.Status=="fail"{return finalize(item.Target.ID,started,results)};l3,data:=contract(item.Target,item.Config);results=append(results,l3);if l3.Status=="fail"{return finalize(item.Target.ID,started,results)};results=append(results,dataAssertions(item.Config,data));return finalize(item.Target.ID,started,results)}
func finalize(id string,started time.Time,results []result)submittedRun{for len(results)<4{results=append(results,result{Layer:len(results)+1,Status:"skip",Checked:time.Now().UTC()})};status:="pass";for _,r:=range results{if r.Status=="fail"{status="fail"}};return submittedRun{TargetID:id,Started:started,Finished:time.Now().UTC(),Status:status,Results:results}}
func connectivity(t target,c probeConfig)result{s:=time.Now();r:=result{Layer:1,Status:"pass",Checked:s.UTC()};u,e:=url.Parse(t.BaseURL);if e!=nil{r.Status="fail";r.Error="invalid target URL";return r};port:=u.Port();if port==""{if u.Scheme=="https"{port="443"}else{port="80"}};timeout:=time.Duration(c.L1.Timeout)*time.Millisecond;if timeout==0{timeout=3*time.Second};conn,e:=net.DialTimeout("tcp",net.JoinHostPort(u.Hostname(),port),timeout);r.Latency=int(time.Since(s).Milliseconds());if e!=nil{r.Status="fail";r.Error="connectivity failed: "+e.Error()}else{conn.Close()};return r}
func endpoint(t target,c probeConfig)string{return strings.TrimRight(t.BaseURL,"/")+"/"+strings.TrimLeft(c.L3.Path,"/")}
func call(t target,c probeConfig)(*http.Response,map[string]any,error){method:=c.L3.Method;if method==""{method="GET"};var body []byte;if t.Type=="graphql"&&c.L3.Query!=""{method="POST";body,_=json.Marshal(map[string]string{"query":c.L3.Query})};req,e:=http.NewRequest(method,endpoint(t,c),bytes.NewReader(body));if e!=nil{return nil,nil,e};if len(body)>0{req.Header.Set("Content-Type","application/json")};if c.L2.AuthType=="bearer"{token:=os.Getenv(c.L2.TokenEnvVar);if token==""{return nil,nil,fmt.Errorf("token environment variable is not set")};header:=c.L2.HeaderName;if header==""{header="Authorization"};req.Header.Set(header,"Bearer "+token)};resp,e:=(&http.Client{Timeout:30*time.Second}).Do(req);if e!=nil{return nil,nil,e};defer resp.Body.Close();var data map[string]any;e=json.NewDecoder(resp.Body).Decode(&data);return resp,data,e}
func auth(t target,c probeConfig)result{r:=result{Layer:2,Status:"pass",Checked:time.Now().UTC()};if c.L2.AuthType==""||c.L2.AuthType=="none"{return r};s:=time.Now();resp,_,e:=call(t,c);r.Latency=int(time.Since(s).Milliseconds());if e!=nil{r.Status="fail";r.Error="auth request failed: "+e.Error();return r};expected:=c.L2.Expected;if expected==0{expected=200};if resp.StatusCode!=expected{r.Status="fail";r.Error=fmt.Sprintf("expected auth status %d, got %d",expected,resp.StatusCode)};return r}
func contract(t target,c probeConfig)(result,map[string]any){s:=time.Now();r:=result{Layer:3,Status:"pass",Checked:s.UTC()};resp,data,e:=call(t,c);r.Latency=int(time.Since(s).Milliseconds());if e!=nil{r.Status="fail";r.Error="contract request failed: "+e.Error();return r,nil};expected:=c.L3.Expected;if expected==0{expected=200};if resp.StatusCode!=expected{r.Status="fail";r.Error=fmt.Sprintf("expected status %d, got %d",expected,resp.StatusCode)};return r,data}
func dataAssertions(c probeConfig,data map[string]any)result{r:=result{Layer:4,Status:"pass",Checked:time.Now().UTC()};for _,a:=range c.L4.Assertions{v,ok:=data[a.Field];if a.Rule=="exists"&&!ok||a.Rule=="non_empty"&&(!ok||fmt.Sprint(v)==""){r.Status="fail";r.Error="data assertion failed: "+a.Field;return r}};return r}
