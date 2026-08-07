#!/bin/sh
set -eu

if ! grep -q ' /sys/kernel/config configfs ' /proc/mounts 2>/dev/null; then
	if mount -t configfs none /sys/kernel/config 2>/dev/null; then
		echo "mounted configfs at /sys/kernel/config"
	else
		echo "warning: ConfigFS mount skipped/failed (need CAP_SYS_ADMIN); ConfigFS-TSM unavailable" >&2
	fi
fi

if [ ! -c /dev/sev-guest ]; then
	if [ -f /sys/class/misc/sev-guest/dev ]; then
		major_minor=$(cat /sys/class/misc/sev-guest/dev)
		major=$(echo "$major_minor" | cut -d: -f1)
		minor=$(echo "$major_minor" | cut -d: -f2)
		if mknod /dev/sev-guest c "$major" "$minor" 2>/dev/null; then
			chmod 644 /dev/sev-guest
			echo "created /dev/sev-guest ($major:$minor)"
		else
			echo "warning: could not create /dev/sev-guest (need CAP_MKNOD)" >&2
		fi
	else
		echo "warning: /sys/class/misc/sev-guest/dev not found; raw hardware derivation may fail" >&2
	fi
fi

exec /usr/local/bin/sealed-shim "$@"
