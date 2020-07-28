# A list of CVE writeups and poc's for Kubernetes

* [CVE-2017-1002101](https://kubernetes.io/blog/2018/04/04/fixing-subpath-volume-vulnerability/) - Accessing files outside of a subpath volume mount via symlinks
* [CVE-2017-1002102](https://github.com/kubernetes/kubernetes/issues/60814) - Arbitrary file deletion in host filesystem
* [CVE-2018-1002105](https://discuss.kubernetes.io/t/kubernetes-security-announcement-v1-10-11-v1-11-5-v1-12-3-released-to-address-cve-2018-1002105/3700) - Privesc via API request crafting. [PoC 1](https://github.com/alexivkin/kubepwn/tree/master/CVEs/CVE-2018-1002105-1)  [source](https://github.com/gravitational/cve-2018-1002105), [PoC 2](https://github.com/alexivkin/kubepwn/tree/master/CVEs/CVE-2018-1002105-2) [source](https://github.com/evict/poc_CVE-2018-1002105)
* [CVE-2018-18264](https://discuss.kubernetes.io/t/security-release-of-dashboard-v1-10-1-cve-2018-18264/4069) - Wide open dashboard
* [CVE-2019-9946](https://discuss.kubernetes.io/t/announce-security-release-of-kubernetes-affecting-certain-network-configurations-with-cni-releases-1-11-9-1-12-7-1-13-5-and-1-14-0-cve-2019-9946/5713) - CNI iptables misuse
* [CVE-2019-5736](https://aws.amazon.com/blogs/compute/anatomy-of-cve-2019-5736-a-runc-container-escape/) - A container escape by overwriting runc binary. [PoC 1](https://github.com/alexivkin/kubepwn/tree/master/CVEs/CVE-2019-5736-1), [PoC 2](https://github.com/alexivkin/kubepwn/tree/master/CVEs/CVE-2019-5736-2)
* [CVE-2019-11245](https://discuss.kubernetes.io/t/security-regression-in-kubernetes-kubelet-v1-13-6-and-v1-14-2-only-cve-2019-11245/6584) - Kubelet security regression
* [CVE-2019-11246](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11246) - Container tar binary can mess with the client that's running `kubectl cp`
* [CVE-2019-11247](https://www.stackrox.com/post/2019/08/how-to-remediate-kubernetes-security-vulnerability-cve-2019-11247/) - modifying CRDs across the cluster
* [CVE-2019-11251](https://discuss.kubernetes.io/t/announce-security-release-of-kubectl-versions-v1-16-0-1-15-4-1-14-7-and-1-13-11-cve-2019-11251/7993) - kubectl cp dir traversal via symlinks
* [CVE-2019-11253](https://discuss.kubernetes.io/t/announce-cve-2019-11253-denial-of-service-vulnerability-from-malicious-yaml-or-json-payloads/8349) - denial of service vulnerability from malicious YAML or JSON
* [CVE-2019-16276](https://groups.google.com/forum/?utm_medium=email&utm_source=footer#!topic/kubernetes-security-announce/PtsUCqFi4h4) - API Authenticating Proxy bypass via HTTP Protocol Violation in Go’s net/http Library
* [CVE-2019-1002101](https://discuss.kubernetes.io/t/announce-security-release-of-kubernetes-kubectl-potential-directory-traversal-releases-1-11-9-1-12-7-1-13-5-and-1-14-0-cve-2019-1002101/5712) - Dir [traversal](https://www.twistlock.com/labs-blog/disclosing-directory-traversal-vulnerability-kubernetes-copy-cve-2019-1002101/) via copy
* [CVE-2020-8551](https://github.com/kubernetes/kubernetes/issues/89377) - Kubelet DoS via /etc/hosts stuffing
* [CVE-2020-8552](https://github.com/kubernetes/kubernetes/issues/89378) - API server DoS OOM
* [CVE-2020-8555](https://github.com/kubernetes/kubernetes/issues/91542) - Half-Blind SSRF in kube-controller-manager. [Full writeup](https://medium.com/@BreizhZeroDayHunters/when-its-not-only-about-a-kubernetes-cve-8f6b448eafa8)
* [CVE-2020-13597, CVE-2020-10749, CVE-2020-13401](https://github.com/kubernetes/kubernetes/issues/91507) - MitM attacks via IPv6 rogue router for CNI like Calico, Flannel, WaveNet
* [CVE-2020-8557](https://issues.k8s.io/93032) - Node disk DOS by writing to container /etc/hosts
* [CVE-2020-8558](https://issues.k8s.io/90259) - net.ipv4.conf.all.route_localnet=1 setting allows for neighboring hosts to bypass localhost boundary. [PoC](https://github.com/alexivkin/kubepwn/tree/master/CVEs/CVE-2020-8558) [source](https://github.com/tabbysable/POC-2020-8558)
* [CVE-2020-8559](https://issues.k8s.io/92914) - Privilege escalation from compromised node to cluster.  [PoC](https://github.com/alexivkin/kubepwn/tree/master/CVEs/CVE-2020-8559) [source](https://github.com/tdwyer/CVE-2020-8559)

Know more? Create an issue or send me a pull request.

## CVEs that are not directly Kubernetes related but may affect it

* Golang CVEs (including all the dependent modules, especially protobuf/gRPC)
* Kernel CVEs
