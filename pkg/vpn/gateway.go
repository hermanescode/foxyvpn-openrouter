package vpn

import (
	"os/exec"
	"strings"
)

func IsGatewayEnabled() bool {
	out, err := exec.Command("sh", "-c", "iptables -t nat -L PREROUTING 2>/dev/null | grep -q FOXYVPN && echo 1 || echo 0").Output()
	return strings.TrimSpace(string(out)) == "1" && err == nil
}

func SetGatewayEnabled(enable bool) (string, error) {
	if enable {
		cmd := `
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
`
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		return string(out), err
	}

	cmd := `
iptables -t nat -D PREROUTING -j FOXYVPN 2>/dev/null || true
iptables -t nat -F FOXYVPN 2>/dev/null || true
iptables -t nat -X FOXYVPN 2>/dev/null || true
`
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}
