# A collection of resources about Kubernetes security

Check out the folders here:

* [CVEs and PoCs](CVEs/)
* [Publications](Publications/)
* [Surveys](Surveys/)
* [Talks](Talks/)
* [Tools](Tools/)

For container related resources check my [other repo](https://github.com/alexivkin/containerpwn)

## Tools

### Red

* [auger](https://github.com/jpbetz/auger) - Directly access data objects stored in `etcd` by `kubernetes
* [kubeletmein](https://www.4armed.com/blog/kubeletmein-kubelet-hacking-tool/) - for GKE and DOKS
* [dopwn](https://github.com/4ARMED/dopwn) - DigitalOcean Kubernetes Pwner
* [go-pillage-registries](https://github.com/nccgroup/go-pillage-registries) - Docker registry scrapper
* [peirates](https://github.com/inguardians/peirates) - Kubernetes pentesting tool
* [Kubetap](https://soluble-ai.github.io/kubetap/) - Sniffing kubernetes traffic

### Purple

* [clusterdump](Tools/kubernetes-cluster-dump.sh) - full cluster export into jsons using both native and specialized exports
* [Managed Kubernetes Inspection Tool](https://github.com/darkbitio/mkit) and [its AKS profile](https://github.com/darkbitio/inspec-profile-aks)
* [Kubiscan](https://github.com/cyberark/kubiscan) - Cyberark's scanner for misconfigurations
* [kubeletctl](https://github.com/cyberark/kubeletctl) - an unofficial ctl tool for kubelet APIs
* [Kubectl images](https://github.com/chenjiandongx/kubectl-images) - Kubectl plugin to list images for all pods and containers
* [Kube-bench](https://github.com/aquasecurity/kube-bench) - Checking configuration weaknesses and bad defaults, check cluster against CIS-Benchmarks
* [Kubesec](https://github.com/controlplaneio/kubesec) - Kubernets manifests and helm charts security risk analysis
* [kube-scan](https://github.com/octarinesec/kube-scan) - Kubernetes risk assessment
* [Rakess](https://github.com/corneliusweig/rakkess) - kubectl plugin to show an access matrix for server resources
* [audit2rbac](https://github.com/liggitt/audit2rbac) - RBAC config review
* [kubeaudit](https://github.com/Shopify/kubeaudit) - Various security config checks

### Blue

#### Policy management

* [k-rail](https://github.com/cruise-automation/k-rail) - a workload policy enforcement tool for Kubernetes. Aims to bring more workload oriented security
* [Kyverno](https://github.com/nirmata/kyverno) - Policy Management tool
* [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) -  general-purpose policy engine that can be used as a Kubernetes admission controller.

#### Vuln detection and management

* [Polaris](https://github.com/reactiveops/polaris) - validates configurations for best practices.
* [Starboard](https://github.com/aquasecurity/starboard) - OSS aquasec tool to run multiple tools in the cluster for audit
* [Checkov](https://github.com/bridgecrewio/checkov) - static code analysis for IaC deployment tools, now supports kubernetes

#### Image scanners

* [Anchore](https://github.com/anchore/anchore-engine)
* [Clair](https://github.com/quay/clair)
* [Trivy](https://github.com/aquasecurity/trivy)
* [Vuls.io](https://vuls.io/) - OVAL based scanner
* [Harbor](https://github.com/goharbor/harbor) - Image repo engine that signs and scans contents
* [OpenSCAP](https://www.open-scap.org/) - Not really image specific but includes container support

#### Monitoring

* [Kubernetes Security Dashboard](https://github.com/k8scop/k8s-security-dashboard)
* [K8Guard](https://github.com/k8guard/k8guard-start-from-here) - Monitor for misbehaving resources
* [Falco](https://github.com/falcosecurity/falco) - Real time behavioral activity monitor designed to detect anomalous activity
* [Gatekeeper](https://github.com/open-policy-agent/gatekeeper) - OPA with audit and [konstraint](https://github.com/plexsystems/konstraint), its policy manager
* [Kritis](https://github.com/grafeas/kritis) - Deploy-time scanner and signature checker for [Grafeas](https://github.com/grafeas/grafeas), the 3rd-party artifact tracker. [more about these here](https://www.infoq.com/presentations/supply-grafeas-kritis/)
* [Kube forensics](https://github.com/keikoproj/kube-forensics)

#### Secret vaulting

* [Banzaicloud bank-vaults](https://github.com/banzaicloud/bank-vaults)
* [External Secrets](https://github.com/godaddy/kubernetes-external-secrets) - Shim for AWS Secrets Manager and HashiCorp Vault

## Trainings, Workshops and Tutorials

* [KubeCon 2019 Attacking and Devending K8s clusters](https://securekubernetes.com/) - walkthrough guide to get the basics down
* [BSidesSF 2020 K8s security training](https://securek8s.dev/exercise/) - [source code](https://github.com/stackrox/bsidessf-2020-workshop)
* [NodyHub's K8s CTF](https://github.com/NodyHub/k8s-ctf-rocks/)
* [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)- intentionally vulnerable k8s deployment
* [Attacking and Auditing Docker Containers and Kubernetes Clusters](https://github.com/appsecco/attacking-and-auditing-docker-containers-and-kubernetes-clusters ) - Materials from 3 day hands on training that we have delivered at security conferences

## Good reads

### Introductory articles

* [Why kubernetes is complex](https://medium.com/uptime-99/kubernetes-202-making-it-fully-operational-7416e4bb15ab)
* [Wilson Mar's K8s](https://wilsonmar.github.io/kubernetes/)
* [GKE hardening advice](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
* [AKS Security concepts](https://docs.microsoft.com/en-us/azure/aks/concepts-security)

### K8s Security concepts

* [Tools and Methods for Auditing Kubernetes RBAC Policies](https://www.nccgroup.com/us/about-us/newsroom-and-events/blog/2019/august/tools-and-methods-for-auditing-kubernetes-rbac-policies/)
* [Image integrity with Notary](https://blog.mi.hdm-stuttgart.de/index.php/2016/09/13/exploring-docker-security-part-3-docker-content-trust/)
* [Setting up Pod Security Policies](https://octetz.com/docs/2018/2018-12-07-psp/)
* [Enhancing Kubernetes Security with Pod Security Policies](https://rancher.com/blog/2020/pod-security-policies-part-1)
* [Webhooks and sidecars](https://medium.com/dowjones/how-did-that-sidecar-get-there-4dcd73f1a0a4)
* [Using OPA and CRDs for security](https://neuvector.com/cloud-security/opa-crd/)
* [K8s audit](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/), Google's [audit logging](https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging) and [auditd](https://cloud.google.com/kubernetes-engine/docs/how-to/linux-auditd-logging)

### Threat modeling

* [K8s threat models](https://www.marcolancini.it/2020/blog-kubernetes-threat-modelling/)
* [Threat Matrix for Kubernetes](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)
* [Trail of Bits kubernetes audit](https://github.com/trailofbits/audit-kubernetes)
* [GKE security notices](https://cloud.google.com/kubernetes-engine/docs/security-bulletins)
* [CIS Benchmark](https://www.cisecurity.org/benchmark/kubernetes/)

### Attacks

* [Using CAP_NET_RAW for DNS Spoofing](https://blog.aquasec.com/dns-spoofing-kubernetes-clusters)
* [Capturing all the flags in BSidesSF CTF by pwning our infrastructure](https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0)
* [KubeCon Slides](https://sbueringer.github.io/kubecon-slides)

## Helpful red-team one-liners

* Istio API - `curl -sL https://github.com/istio/istio/releases/download/1.4.0-beta.0/istioctl-1.4.0-beta.0-linux.tar.gz | tar xzf -`
* Kubernetes API - `curl -sLO https://storage.googleapis.com/kubernetes-release/release/v1.16.0/bin/linux/amd64/kubectl; chmod u+x kubectl`
* Docker registy - `curl -sL https://github.com/genuinetools/reg/releases/download/v0.16.0/reg-linux-amd64 -o reg; chmod u+x reg`
* Better alternative to the docker CLI - `curl -sL https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.16.1/crictl-v1.16.1-linux-amd64.tar.gz | tar zxf -`
* Etcd API- `curl -sL https://github.com/etcd-io/etcd/releases/download/v3.4.3/etcd-v3.4.3-linux-amd64.tar.gz | tar zxf -`
* GCP and DO metadata for easy kube pwnage `curl -sL https://github.com/4ARMED/kubeletmein/releases/download/v0.6.5/kubeletmein_0.6.5_linux_amd64 -o kubeletmein; chmod u+x kubeletmein`
