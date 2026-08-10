// PID 1 for the sealed boot initrd: mount essentials, apply host env
// (virtio-blk / optional fw_cfg), bring up the NIC, print launch
// MEASUREMENT, then exec /sealed-shim.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-sev-guest/client"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const fwcfgEnvPath = "/sys/firmware/qemu_fw_cfg/by_name/opt/nexqloud/env/raw"

func main() {
	_ = os.MkdirAll("/dev", 0755)
	_ = os.MkdirAll("/proc", 0755)
	_ = os.MkdirAll("/sys", 0755)
	_ = os.MkdirAll("/tmp", 0755)
	_ = os.MkdirAll("/sys/kernel/config", 0755)

	_ = syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, "")
	_ = syscall.Mount("proc", "/proc", "proc", 0, "")
	_ = syscall.Mount("sysfs", "/sys", "sysfs", 0, "")
	_ = syscall.Mount("configfs", "/sys/kernel/config", "configfs", 0, "")

	ensureSevGuest()

	log("SEALED_OK initrd userspace up")
	if err := dumpMeasurement(); err != nil {
		log("SEALED_MEASURE_FAIL " + err.Error())
	}

	if err := loadGuestEnv(); err != nil {
		log("SEALED_ENV " + err.Error())
	}

	if err := setupNetworkFromEnv(); err != nil {
		log("SEALED_NET_FAIL " + err.Error())
	}
	if err := setupResolvConfFromEnv(); err != nil {
		log("SEALED_DNS_FAIL " + err.Error())
	}
	disableIPv6()
	_ = os.Setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")

	shim := "/sealed-shim"
	if _, err := os.Stat(shim); err != nil {
		log("SEALED_NO_SHIM " + err.Error() + " — idling")
		for {
			time.Sleep(time.Hour)
		}
	}

	args := []string{shim, "--addr", ":8080"}
	if os.Getenv("NEXQLOUD_DEV") == "1" {
		args = append(args, "--dev")
	}

	log("SEALED_EXEC " + strings.Join(args, " "))
	err := syscall.Exec(shim, args, os.Environ())
	log("SEALED_EXEC_FAIL " + err.Error())
	for {
		time.Sleep(time.Hour)
	}
}

func loadGuestEnv() error {
	raw, src, err := readGuestEnvBytes()
	if err != nil {
		return err
	}
	n := 0
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" {
			continue
		}
		if err := os.Setenv(key, val); err != nil {
			return err
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("no KEY=VALUE lines in guest env (%s)", src)
	}
	log(fmt.Sprintf("SEALED_ENV_OK %s keys=%d", src, n))
	return nil
}

func readGuestEnvBytes() ([]byte, string, error) {
	if raw, err := readEnvFromVirtioBlk(); err == nil {
		return raw, "virtio-blk:" + envDiskSerial, nil
	} else {
		log("SEALED_ENV_DISK " + err.Error())
	}
	if raw, err := os.ReadFile(fwcfgEnvPath); err == nil {
		return raw, "fw_cfg-sysfs", nil
	}
	return nil, "", fmt.Errorf("no guest env (need virtio-blk serial=%s)", envDiskSerial)
}

func setupNetworkFromEnv() error {
	cidr := strings.TrimSpace(os.Getenv("NEXQLOUD_NET_IP"))
	if cidr == "" {
		log("SEALED_NET_SKIP NEXQLOUD_NET_IP unset")
		return nil
	}
	iface := strings.TrimSpace(os.Getenv("NEXQLOUD_NET_IFACE"))
	if iface == "" {
		iface = "eth0"
	}
	gw := strings.TrimSpace(os.Getenv("NEXQLOUD_NET_GW"))

	link, err := waitLink(iface, 15*time.Second)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parse NEXQLOUD_NET_IP %q: %w", cidr, err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("AddrReplace: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("LinkSetUp: %w", err)
	}
	if gw != "" {
		gwIP := net.ParseIP(gw)
		if gwIP == nil {
			return fmt.Errorf("parse NEXQLOUD_NET_GW %q", gw)
		}
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        gwIP,
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("RouteReplace: %w", err)
		}
	}
	log(fmt.Sprintf("SEALED_NET_OK %s %s gw=%s", iface, cidr, gw))
	return nil
}

func setupResolvConfFromEnv() error {
	dns := strings.TrimSpace(os.Getenv("NEXQLOUD_NET_DNS"))
	if dns == "" {
		log("SEALED_DNS_SKIP NEXQLOUD_NET_DNS unset")
		return nil
	}
	var primary string
	for _, ns := range strings.Fields(strings.ReplaceAll(dns, ",", " ")) {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			primary = ns
			break
		}
	}
	if primary == "" {
		return fmt.Errorf("NEXQLOUD_NET_DNS empty after parse")
	}
	// One nameserver only: Go rotates across all entries and a flaky secondary
	// (e.g. 8.8.8.8 blocked on some nanoserver egress paths) burns KDS budget.
	body := "# written by sealed-init\noptions timeout:2 attempts:2\nnameserver " + primary + "\n"
	if err := os.WriteFile("/etc/resolv.conf", []byte(body), 0644); err != nil {
		return err
	}
	if extras := strings.TrimSpace(strings.TrimPrefix(dns, primary)); extras != "" {
		log("SEALED_DNS_OK " + primary + " (ignored extra: " + strings.TrimSpace(extras) + ")")
	} else {
		log("SEALED_DNS_OK " + primary)
	}
	return nil
}

func disableIPv6() {
	for _, p := range []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
	} {
		if err := os.WriteFile(p, []byte("1\n"), 0644); err != nil {
			log("SEALED_IPV6_DISABLE " + p + " " + err.Error())
			return
		}
	}
	log("SEALED_IPV6_DISABLED")
}

func waitLink(name string, timeout time.Duration) (netlink.Link, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		link, err := netlink.LinkByName(name)
		if err == nil {
			return link, nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout")
	}
	return nil, fmt.Errorf("wait for %s: %w", name, lastErr)
}

func ensureSevGuest() {
	if _, err := os.Stat("/dev/sev-guest"); err == nil {
		return
	}
	raw, err := os.ReadFile("/sys/class/misc/sev-guest/dev")
	if err != nil {
		log("SEALED_SEV_GUEST_SYSFS " + err.Error())
		return
	}
	var major, minor int
	if _, err := fmt.Sscanf(string(raw), "%d:%d", &major, &minor); err != nil {
		log("SEALED_SEV_GUEST_PARSE " + err.Error())
		return
	}
	if err := syscall.Mknod("/dev/sev-guest", syscall.S_IFCHR|0644, int(unix.Mkdev(uint32(major), uint32(minor)))); err != nil {
		log("SEALED_SEV_GUEST_MKNOD " + err.Error())
	}
}

func dumpMeasurement() error {
	d, err := client.OpenDevice()
	if err != nil {
		return fmt.Errorf("open sev-guest: %w", err)
	}
	defer d.Close()
	var reportData [64]byte
	report, err := client.GetReport(d, reportData)
	if err != nil {
		return fmt.Errorf("GetReport: %w", err)
	}
	m := report.GetMeasurement()
	if len(m) == 0 {
		return fmt.Errorf("empty measurement")
	}
	log("SEALED_MEASUREMENT " + hex.EncodeToString(m))
	return nil
}

func log(msg string) {
	fmt.Println(msg)
	_ = os.Stdout.Sync()
}
