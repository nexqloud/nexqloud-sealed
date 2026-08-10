package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const envDiskSerial = "nexqloud-env"

func readEnvFromVirtioBlk() ([]byte, error) {
	deadline := time.Now().Add(15 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		raw, err := tryReadEnvDisk()
		if err == nil {
			return raw, nil
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("timeout waiting for env disk serial=%s", envDiskSerial)
	}
	return nil, last
}

func tryReadEnvDisk() ([]byte, error) {
	ents, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	var matched []string
	var vdCandidates []string
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		if strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "xvd") || strings.HasPrefix(name, "nvme") {
			vdCandidates = append(vdCandidates, name)
		}
		if serialOfBlock(name) == envDiskSerial {
			matched = append(matched, name)
		}
	}
	pick := matched
	if len(pick) == 0 && len(vdCandidates) == 1 {
		pick = vdCandidates
	}
	if len(pick) == 0 {
		return nil, fmt.Errorf("no block device with serial %s (have %v)", envDiskSerial, vdCandidates)
	}
	dev := pick[0]
	path := "/dev/" + dev
	if err := ensureBlockDev(dev); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	raw = trimEnvBytes(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s empty", path)
	}
	return raw, nil
}

func serialOfBlock(name string) string {
	candidates := []string{
		filepath.Join("/sys/block", name, "serial"),
		filepath.Join("/sys/block", name, "device", "serial"),
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		return strings.TrimSpace(string(b))
	}
	return ""
}

func ensureBlockDev(name string) error {
	path := "/dev/" + name
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join("/sys/block", name, "dev"))
	if err != nil {
		return err
	}
	var major, minor int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d:%d", &major, &minor); err != nil {
		return fmt.Errorf("parse %s dev: %w", name, err)
	}
	return syscall.Mknod(path, syscall.S_IFBLK|0600, int(unix.Mkdev(uint32(major), uint32(minor))))
}

func trimEnvBytes(raw []byte) []byte {
	for len(raw) > 0 && raw[len(raw)-1] == 0 {
		raw = raw[:len(raw)-1]
	}
	return raw
}
