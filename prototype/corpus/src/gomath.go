// gomath — a Go analog of mathlib.c (same small call graph) for the re-anchoring corpus.
// A different toolchain entirely: a static binary with a large Go runtime, Go's calling
// convention, and `main.`-prefixed symbols. The point is robustness — the annotated user
// functions are a needle in a haystack of runtime functions; the matcher must still find them.
//
//go:build ignore

package main

import (
	"fmt"
	"os"
	"strconv"
)

//go:noinline
func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

//go:noinline
func fib(n uint) uint64 {
	if n < 2 {
		return uint64(n)
	}
	return fib(n-1) + fib(n-2)
}

//go:noinline
func factorial(n uint) uint64 {
	var r uint64 = 1
	for i := uint(2); i <= n; i++ {
		r *= uint64(i)
	}
	return r
}

//go:noinline
func sumTo(n uint) uint64 {
	var s uint64
	for i := uint(1); i <= n; i++ {
		s += uint64(i)
	}
	return s
}

func main() {
	n := uint(10)
	if len(os.Args) > 1 {
		if v, err := strconv.Atoi(os.Args[1]); err == nil {
			n = uint(v)
		}
	}
	fmt.Printf("gcd(%d,48)=%d\n", n, gcd(uint64(n), 48))
	fmt.Printf("fib(%d)=%d\n", n, fib(n))
	fmt.Printf("fact(%d)=%d\n", n, factorial(n))
	fmt.Printf("sum(%d)=%d\n", n, sumTo(n))
}
