// PID 1 for the sealed boot initrd: mount essentials, print launch
// MEASUREMENT, then exec /sealed-shim from the same initrd.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/google/go-sev-guest/client"
	"golang.org/x/sys/unix"
)

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

	shim := "/sealed-shim"
	if _, err := os.Stat(shim); err != nil {
		log("SEALED_NO_SHIM " + err.Error() + " — idling")
		for {
			time.Sleep(time.Hour)
		}
	}

	if os.Getenv("NEXQLOUD_DEV") == "" {
		_ = os.Setenv("NEXQLOUD_DEV", "1")
	}

	log("SEALED_EXEC " + shim)
	err := syscall.Exec(shim, []string{shim, "--dev", "--addr", ":8080"}, os.Environ())
	log("SEALED_EXEC_FAIL " + err.Error())
	for {
		time.Sleep(time.Hour)
	}
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
