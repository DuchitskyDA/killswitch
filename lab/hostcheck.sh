#!/bin/sh
# Снимок хоста до и после прогона. Ничего не меняет. KSL_SERVICES — живые службы хоста для сверки.
# nft-raw плавает сам по себе (счётчики ufw и наборы fail2ban); сравнивать по nft-stateless.
echo "services: $(systemctl is-active ${KSL_SERVICES:-} 2>/dev/null | tr '\n' ' ')"
echo "nft-raw: $(nft list ruleset 2>/dev/null | sha256sum)"
echo "nft-stateless: $(nft -s list ruleset 2>/dev/null | sha256sum)"
echo "route4: $(ip route | sha256sum)"
echo "route6: $(ip -6 route | sha256sum)"
echo "links: $(ip -br link | sha256sum)"
echo "sysctl forward v4 v6: $(sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.forwarding | tr '\n' ' ')"
echo "netns ksl-*: $(ls /run/netns 2>/dev/null | grep -c '^ksl-')"
echo "scope ksl-lab: $(systemctl is-active ksl-lab.scope 2>/dev/null)"
