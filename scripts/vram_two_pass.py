#!/usr/bin/env python3
"""Two-pass VRAM wipe using libcudart (marker 0xA5 then zeroes)."""
from __future__ import annotations

import ctypes
import ctypes.util
import sys


MARKER = 0xA5


def load_cudart():
    names = [
        "libcudart.so",
        "libcudart.so.12",
        "libcudart.so.11",
    ]
    found = ctypes.util.find_library("cudart")
    if found:
        names.insert(0, found)
    last = None
    for name in names:
        try:
            return ctypes.CDLL(name)
        except OSError as e:
            last = e
    raise OSError(f"libcudart not found (tried {names}): {last}")


def main() -> int:
    try:
        cudart = load_cudart()
    except OSError as e:
        print(f"{e}", file=sys.stderr)
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
    cudart.cudaGetDeviceCount.argtypes = [ctypes.POINTER(ctypes.c_int)]
    cudart.cudaGetDeviceCount.restype = ctypes.c_int
    cudart.cudaSetDevice.argtypes = [ctypes.c_int]
    cudart.cudaSetDevice.restype = ctypes.c_int

    n = ctypes.c_int(0)
    if cudart.cudaGetDeviceCount(ctypes.byref(n)) != 0 or n.value < 1:
        print("no CUDA device visible", file=sys.stderr)
        return 1
    if cudart.cudaSetDevice(0) != 0:
        print("cudaSetDevice(0) failed", file=sys.stderr)
        return 1

    free_b = ctypes.c_size_t()
    total_b = ctypes.c_size_t()
    if cudart.cudaMemGetInfo(ctypes.byref(free_b), ctypes.byref(total_b)) != 0:
        print("cudaMemGetInfo failed", file=sys.stderr)
        return 1

    # Leave headroom so llama (sharing the GPU) can stay alive.
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

    print(f"wiped_bytes={size} free_before={free_b.value} total={total_b.value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
