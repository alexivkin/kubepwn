# A collection of resources about Kubernetes security

Check out the folders here:

* [Publications](Publications/)
* [Surveys](Surveys/)
* [Talks](Talks/)
* [Tools](Tools/)

For container related resources check my [other repo](https://github.com/alexivkin/containerpwn)

## Introductory articles

* [Why kubernetes is complex](https://medium.com/uptime-99/kubernetes-202-making-it-fully-operational-7416e4bb15ab)
* [Wilson Mar's K8s](https://wilsonmar.github.io/kubernetes/)
* [GKE advice](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)

## Tools

* [audit2rbac](https://github.com/liggitt/audit2rbac)
* [k-rail  Workload policy review/enforcement tool](https://github.com/cruise-automation/k-rail)
* [kubeletmein for GKE and DOKS](https://www.4armed.com/blog/kubeletmein-kubelet-hacking-tool/)
* [auger Directly access data objects stored in `etcd` by `kubernetes](https://github.com/jpbetz/auger)
* [DigitalOcean Kubernetes Pwner](https://github.com/4ARMED/dopwn)
* [Docker registry scrapper](https://github.com/nccgroup/go-pillage-registries)
* [Kubernetes Security Dashboard](https://github.com/k8scop/k8s-security-dashboard)
* [Check cluster against CIS-Benchmarks](https://github.com/aquasecurity/kube-bench)
* [Kube forensics](https://github.com/keikoproj/kube-forensics)
* [Kubernetes risk assessment](https://github.com/octarinesec/kube-scan)
* [Another security risk analysis for Kubernetes resources](https://github.com/controlplaneio/kubesec)
* [Another RBAC analyzer](https://github.com/cyberark/KubiScan)
* [Managed Kubernetes Inspection Tool](https://github.com/darkbitio/mkit)
* [Kubernetes pentesting tool](https://github.com/inguardians/peirates)
* [NodyHub's K8s CTF](https://github.com/NodyHub/k8s-ctf-rocks/)

## Reads and presos

* [KubeCon Slides](https://sbueringer.github.io/kubecon-slides)
* [Trail of Bits kubernetes audit](https://github.com/trailofbits/audit-kubernetes)

## Standards and recommendations

* [CIS Benchmark[(https://www.cisecurity.org/benchmark/kubernetes/)
* [Gartner - Best Practices for Running Containers and Kubernetes in Production](https://www.gartner.com/en/documents/3902966/best-practices-for-running-containers-and-kubernetes-in-)

## Documentation

### Authentication and authorization

* https://kubernetes.io/docs/reference/access-authn-authz/rbac
* https://kubernetes.io/docs/reference/access-authn-authz/authentication/
* https://kubernetes.io/docs/reference/access-authn-authz/authorization/
* https://kubernetes.io/docs/admin/kubelet-authentication-authorization
* https://kubernetes.io/docs/concepts/configuration/secret/
* https://kubernetes.io/docs/concepts/policy/pod-security-policy/

### Audit logging

* https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
* https://cloud.google.com/kubernetes-engine/docs/how-to/linux-auditd-logging
* https://kubernetes.io/docs/tasks/debug-application-cluster/audit/

## Notary

* https://blog.mi.hdm-stuttgart.de/index.php/2016/09/13/exploring-docker-security-part-3-docker-content-trust/

### Webhooks and sidecars

* https://medium.com/dowjones/how-did-that-sidecar-get-there-4dcd73f1a0a4

## Hacks

* https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0

## Docker swarm

* managing secrets in a docker swarm - https://docs.docker.com/engine/swarm/secrets/#read-more-about-docker-secret-commands
* secret management-  https://www.katacoda.com/courses/docker-security/vault-secrets https://www.katacoda.com/courses/docker-security/docker-volume-libsecret

## Windows kubernetes

* https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/
