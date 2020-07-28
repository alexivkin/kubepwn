# Overview

CVE-2020-8558 is a Kubernetes venerability which was published because kube-proxy *unexpectedly* makes localhost-bound host services available to others on the network. I place the emphasis on unexpectedly because this vulnerability is due to a design flaw (oversight), not an implementation flaw (bug). The code does exactly what it says it does, but we all failed to recognize the security implications of that decision.

In order to allow host processes to access NodePort services via the 127.0.0.1(localhost) address, kube-proxy sets the `net.ipv4.conf.all.route_localnet=1` sysctl setting. According to the kernel documentation, this setting makes the kernel "not consider loopback addresses as martian" -- a consequence of which is that they could be accessed by other nodes on the network. That's a big deal if you have sensitive unauthenticated services whose only protection is being bound to localhost!

As of this writing, the Kubernetes community is still working out the best way to address CVE-2020-8558. The two obvious choices are to stop setting the `route_localnet` sysctl in the first place, or to block inappropriately-routed localnet packets using iptables. A fix using the latter strategy has already been released in kubelet >= 1.18.4, 1.17.7, or 1.16.11. You may also apply it yourself by referring to the Kubernetes issue for this CVE, linked below.

# History and Background

Why does setting `net.ipv4.conf.all.route_localnet=1` merit a CVE ID? Primarily because it violates our intuition about IP networks.

Since at least 1989's RFC 1122, packets from the localhost network `127.0.0.1/8` have been treated specially, forbidden from appearing "outside a host". (Please contact me on Twitter if you know of an earlier reference to special properties of 127/8.) Any RFC-compliant host essentially has an implicit, non-removable firewall rule blocking outside access to services bound to 127.0.0.1 (and other IPs in that network -- try pinging 127.127.127.127 if you never have before!) We have come to depend upon and expect that behavior. We frequently run sensitive services without authentication or encryption, and bind them to localhost for safety. For example, plaintext HTTP backends, redis key-value store, and the vestigial Kubernetes api-server insecure port are all usually protected from intrusion this way. We are so used to this behavior that it is an ingrained part of our intuitive sense of what it means to be an IP host. Seen in this light, it's understandable that numerous experts could have overlooked this flaw for so long.

How does it work?

Let's call any entity with an IP address a "node". IP packets are sent from one node to another, identified by the source and destination IP address in the packet header. Every IP node is either a router (called a gateway in RFC1122) or a host. The primary difference is that when a host receives packets destined for someone else's address, it ignores them. A router consults its routing table and retransmits (forwards) packets in an attempt to get them closer to their ultimate destination. A host will know about some locally-connected nodes; to access other nodes, it must send its packets to a locally-connected router. Those local connections may be point-to-point (such as a PPP link or some virtual networks) or shared-medium (such as Ethernet).

Your mailbox can be conceptualized as a point-to-point link between your house and the local post office. To route a packet over a point-to-point link, the host needs only apply the correct destination address and transmit the packet. (This takes place on Layer 3 of the OSI model.) To route a packet over a shared-medium link, the host must first construct a virtual point-to-point circuit across the shared medium. In Ethernet/IP networks, this is done by ARP, on layer 2 of the OSI model. Essentially, if you can transmit an ARP packet, you can tell another host "Hey, I'm over here" and it will believe you. (When this is done inappropriately it is called ARP cache poisoning.) Then you may communicate by putting the appropriate Ethernet source and destination addresses on your packets.

A normal node will never transmit a packet with a destination address of 127.0.0.1, because of RFC 1122. If a normal node receives a packet with a destination address of 127.0.0.1, it will ignore (drop) it, again because of RFC 1122. Setting `net.ipv4.conf.all.route_localnet=1` changes that -- it allows 127.0.0.1 packets to be sent and received as if they were not special.

So, if an attacker has a local connection to a target node with `net.ipv4.conf.all.route_localnet=1`, the attacker can send it a packet with 127.0.0.1 as the destination address, and that target node will respond appropriately as if 127.0.0.1 were a totally normal address. The two most common ways to have a local connection to a target node today are to be on the same Ethernet network (broadcast domain) as the target, or to be a container running on the target.

Note that when normally configured, Linux will not allow the attacker node to transmit normal packets destined for 127.0.0.1. This can be worked-around by reconfiguring the attacker's Linux node (if they have root access), or by forging packets using a raw socket. Raw sockets require only the Linux kernel capability CAP_NET_RAW, which is given by default to unprivileged containers. This means that an attacker-controlled unprivileged container is capable of exploiting CVE-2020-8558.

# Evaluation

In short, if you're using kube-proxy or doing clever things with `net.ipv4.conf.*.route_localnet`, you're exposed. You should spend some time threat modeling to determine how risky that exposure is to you and plan an appropriate mitigation strategy.

Fundamentally, every Linux host with `net.ipv4.conf.all.route_localnet=1` set is vulnerable. Whether that vulnerability is interesting to an attacker depends on several factors:

1) Is the host accessible to the attacker?
2) Are the packets filtered?
3) Are there any interesting services bound to localhost?

To evaluate CVE-2020-8558, you must imagine attackers with various capabilities, and answer these questions from the point of view of those attackers. (Adam Shostack's book "Threat Modeling: Designing for Security" describes this process in great detail.) Two relevant attackers you should certainly consider are an attacker with a node on your Ethernet network, and an attacker who can run code in an unprivileged pod on your host. There may be other interesting attackers you should also consider, depending on your environment and needs.

To illustrate, here's a partially-worked example:

The host is certainly accessible to both attackers; we have assumed it in each case.

The packets may or may not be filtered. You will need to check. In many cloud environments and strictly-managed on-prem networks, packets are blocked if the IP destination fails to match the Ethernet destination expected by the network. This could by itself be game-over for the attacker-with-a-node. If all your nodes have appropriate local firewall rules (such as supplied by an updated kubelet), that will cause both attackers to fail.

There are likely more interesting services than you think. Obviously, the Kubernetes api-server insecure port is a highly inviting target, and you should disable it if you can. Investigate all processes binding to IP addresses in the 127.0.0.0/8 network: do they have robust authentication? If not, they could be exposed via CVE-2020-8558. Even if all your normal localhost services are safe, ephemeral ones can be a concern also. For example, SSH port forwarding is often used to bypass network restrictions for temporary, authorized purposes. By default, SSH-forwarded ports are bound to localhost so that the temporary access is only allowed for authorized users. With CVE-2020-8558, those "safe" port-forwards are available to your attackers, too.

# Tools

## Linux

Assuming you have root on a Linux box on the same broadcast domain as the target, the following configuration settings will allow you to exploit CVE-2020-8558:

```
ip addr add 127.0.0.2/8 dev lo
ip addr del 127.0.0.1/8 dev lo
ip route add 127.0.0.1/32 via YOUR-TARGET-HERE
sysctl net.ipv4.conf.all.route_localnet=1
```

Because some important services (cough, cough, `systemd-resolved`) run on a 127.0.0.0/8 address, we add a new one to prevent breaking the host. Then, the host must forget about its default 127.0.0.1/8 address. Next, we instruct the kernel to route traffic for `127.0.0.1` over the wire to your target, which knows how to access `127.0.0.1`. Finally, we set the infamous sysctl that would otherwise block this configuration from working.

## tst-2020-8558.py

Simple Python script to test for CVE-2020-8558 by sending raw packets. This could be a scapy oneliner, but I wanted to add a little bit more of the comforts of home. It sends a packet to `127.0.0.1` via your target, and looks to see if there is a reply.

## poc-2020-8558.py

Python script to exploit CVE-2020-8558 by allowing ordinary TCP or UDP client applications to communicate with a remote localhost IP via forged packets. Run this script, then use any normal TCP or UDP client (e.g. kubectl or nc) to connect to your fakedestination (198.51.100.1 by default).

Note that the fakedestination needs to be an IP address that never responds to packets and your route to it must be over the same interface as you access your target. In the usual case, both fakedestination and target will be accessible via your default gateway interface, and this will be no big deal.

Because this script uses raw sockets to send and receive the "localhost" packets, it works fine inside a normal unprivileged container.

# End Material
[Kubernetes issue for this CVE on GitHub](https://github.com/kubernetes/kubernetes/issues/92315)

[Kernel IP sysctl documentation](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)

[RFC 1122](https://tools.ietf.org/html/rfc1122)

[Wikipedia: OSI Model](https://en.wikipedia.org/wiki/OSI_model)

[Adam Shostack: Threat Modeling](https://www.threatmodelingbook.com/)

Shout-out to Ian Coldwater, Brad Geesaman, Duffie Cooley, and Laurent Bernaille. Thanks for the thoughts, advice, and lols, y'all. Honk the planet!
