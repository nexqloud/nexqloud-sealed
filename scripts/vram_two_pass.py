#!/usr/bin/env python3
"""Two-pass VRAM wipe using libcudart (marker 0xA5 then zeroes)."""
from __future__ import annotations

import ctypes
import sys


MARKER = 0xA5


def main() -> int:
    try:
        cudart = ctypes.CDLL("libcudart.so")
    except OSError as e:
        print(f"libcudart.so not found: {e}", file=sys.stderr)
        return 1

    cudart.cudaMalloc.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_size_t]
    cudart.cudaMalloc.restype = ctypes.c_int
    cudart.cudaFree.argtypes = [ctypes.c_void_p]
    cudart.cudaFree.restype = ctypes.c_int
    cudart.cudaMemset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
    cudart.cudaMemset.restype = ctypes.c_int
    cudart.cudaDeviceSynchronize.restype = ctypes.c_int
    cudart.cudaMemGetInfo.argtypes = [
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    cudart.cudaMemGetInfo.restype = ctypes.c_int

    free_b = ctypes.c_size_t()
    total_b = ctypes.c_size_t()
    if cudart.cudaMemGetInfo(ctypes.byref(free_b), ctypes.byref(total_b)) != 0:
        print("cudaMemGetInfo failed", file=sys.stderr)
        return 1

    # Leave headroom so the driver/llama process can stay alive.
    reserve = max(64 << 20, int(free_b.value * 0.05))
    size = free_b.value - reserve
    if size < (16 << 20):
        size = min(free_b.value, 16 << 20)
    if size <= 0:
        print("no free VRAM to wipe", file=sys.stderr)
        return 1

    ptr = ctypes.c_void_p()
    if cudart.cudaMalloc(ctypes.byref(ptr), size) != 0:
        print(f"cudaMalloc({size}) failed", file=sys.stderr)
        return 1
    try:
        if cudart.cudaMemset(ptr, MARKER, size) != 0:
            print("cudaMemset marker failed", file=sys.stderr)
            return 1
        if cudart.cudaDeviceSynchronize() != 0:
            print("sync after marker failed", file=sys.stderr)
            return 1
        if cudart.cudaMemset(ptr, 0, size) != 0:
            print("cudaMemset zero failed", file=sys.stderr)
            return 1
        if cudart.cudaDeviceSynchronize() != 0:
            print("sync after zero failed", file=sys.stderr)
            return 1
    finally:
        cudart.cudaFree(ptr)

    print(f"wiped_bytes={size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
