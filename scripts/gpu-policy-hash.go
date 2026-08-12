package main

import (
	"fmt"
	"os"

	"nexqloud-sealed/internal/gpu"
)

func main() {
	h, err := gpu.Hash(gpu.DefaultPolicy())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(h)
}
