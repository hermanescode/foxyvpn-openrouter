package vpn

import (
	"os/exec"
	"strings"
)

func IsGatewayEnabled() bool {
	checkCmd := `
if command -v nft >/dev/null 2>&1; then
    nft list table inet foxyvpn 2>/dev/null | grep -q "foxyvpn" && echo 1 || echo 0
elif command -v iptables >/dev/null 2>&1; then
    iptables -t nat -L PREROUTING 2>/dev/null | grep -q "FOXYVPN" && echo 1 || echo 0
else
    echo 0
fi
`
	out, err := exec.Command("sh", "-c", checkCmd).Output()
	return strings.TrimSpace(string(out)) == "1" && err == nil
}

func SetGatewayEnabled(enable bool) (string, error) {
	if enable {
		cmd := `
if command -v nft >/dev/null 2>&1; then
    nft add table inet foxyvpn 2>/dev/null || true
    nft flush table inet foxyvpn 2>/dev/null || true
    nft 'add chain inet foxyvpn prerouting { type nat hook prerouting priority dstnat - 5; policy accept; }'
    nft 'add rule inet foxyvpn prerouting ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return'
    nft 'add rule inet foxyvpn prerouting meta l4proto tcp tcp dport { 80, 443 } redirect to :1081'
elif command -v iptables >/dev/null 2>&1; then
    iptables -t nat -N FOXYVPN 2>/dev/null || iptables -t nat -F FOXYVPN
    iptables -t nat -A FOXYVPN -d 0.0.0.0/8 -j RETURN
    iptables -t nat -A FOXYVPN -d 10.0.0.0/8 -j RETURN
    iptables -t nat -A FOXYVPN -d 127.0.0.0/8 -j RETURN
    iptables -t nat -A FOXYVPN -d 169.254.0.0/16 -j RETURN
    iptables -t nat -A FOXYVPN -d 172.16.0.0/12 -j RETURN
    iptables -t nat -A FOXYVPN -d 192.168.0.0/16 -j RETURN
    iptables -t nat -A FOXYVPN -d 224.0.0.0/4 -j RETURN
    iptables -t nat -A FOXYVPN -d 240.0.0.0/4 -j RETURN
    iptables -t nat -A FOXYVPN -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 1081
    iptables -t nat -D PREROUTING -j FOXYVPN 2>/dev/null || true
    iptables -t nat -I PREROUTING -j FOXYVPN
else
    echo "Neither nft nor iptables found"
    exit 1
fi
`
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		return string(out), err
	}

	cmd := `
if command -v nft >/dev/null 2>&1; then
    nft delete table inet foxyvpn 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    iptables -t nat -D PREROUTING -j FOXYVPN 2>/dev/null || true
    iptables -t nat -F FOXYVPN 2>/dev/null || true
    iptables -t nat -X FOXYVPN 2>/dev/null || true
fi
`
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}
