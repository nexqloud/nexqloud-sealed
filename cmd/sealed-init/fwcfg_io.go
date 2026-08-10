package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	fwCfgPortSel  = 0x510
	fwCfgPortData = 0x511
	fwCfgSigSel   = 0x0000
	fwCfgDirSel   = 0x0019
	fwCfgEnvName  = "opt/nexqloud/env"
)

// Kata's guest kernel has no CONFIG_FW_CFG_SYSFS; OVMF still uses the
// fw_cfg IO device (kernel-hashes). Read named files via /dev/port.
func readFwcfgFileIO(name string) ([]byte, error) {
	if err := ensureDevPort(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile("/dev/port", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/port: %w", err)
	}
	defer f.Close()

	sig, err := fwcfgRead(f, fwCfgSigSel, 4)
	if err != nil {
		return nil, err
	}
	if string(sig) != "QEMU" {
		return nil, fmt.Errorf("fw_cfg signature %q (want QEMU)", sig)
	}

	countBuf, err := fwcfgRead(f, fwCfgDirSel, 4)
	if err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint32(countBuf)
	if count == 0 || count > 512 {
		return nil, fmt.Errorf("fw_cfg file_dir count %d", count)
	}

	dir, err := fwcfgRead(f, fwCfgDirSel, 4+int(count)*64)
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(count); i++ {
		off := 4 + i*64
		ent := dir[off : off+64]
		size := binary.BigEndian.Uint32(ent[0:4])
		sel := binary.BigEndian.Uint16(ent[4:6])
		n := string(ent[8:56])
		if z := strings.IndexByte(n, 0); z >= 0 {
			n = n[:z]
		}
		if n != name {
			continue
		}
		if size > 1<<20 {
			return nil, fmt.Errorf("fw_cfg %s size %d too large", name, size)
		}
		return fwcfgRead(f, sel, int(size))
	}
	return nil, fmt.Errorf("fw_cfg file %q not found (dir count=%d)", name, count)
}

func ensureDevPort() error {
	if _, err := os.Stat("/dev/port"); err == nil {
		return nil
	}
	return syscall.Mknod("/dev/port", syscall.S_IFCHR|0644, int(unix.Mkdev(1, 4)))
}

func fwcfgRead(f *os.File, sel uint16, n int) ([]byte, error) {
	var selLE [2]byte
	binary.LittleEndian.PutUint16(selLE[:], sel)
	if _, err := f.Seek(fwCfgPortSel, 0); err != nil {
		return nil, err
	}
	if _, err := f.Write(selLE[:]); err != nil {
		return nil, fmt.Errorf("fw_cfg select %#x: %w", sel, err)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		if _, err := f.Seek(fwCfgPortData, 0); err != nil {
			return nil, err
		}
		if _, err := f.Read(out[i : i+1]); err != nil {
			return nil, fmt.Errorf("fw_cfg data %#x byte %d: %w", sel, i, err)
		}
	}
	return out, nil
}
