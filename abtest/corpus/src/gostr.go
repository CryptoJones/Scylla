// gostr — a Go analog of prototype/corpus/src/strutil.c for the A/B parity corpus: string
// handling (reverse, vowel count, palindrome test, word histogram via a map) plus one
// interface dispatch, so the Go corpus has a second, differently-shaped program next to gomath.
//
//go:build ignore

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

//go:noinline
func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

//go:noinline
func countVowels(s string) int {
	n := 0
	for _, c := range strings.ToLower(s) {
		switch c {
		case 'a', 'e', 'i', 'o', 'u':
			n++
		}
	}
	return n
}

//go:noinline
func isPalindrome(s string) bool {
	t := strings.ToLower(strings.ReplaceAll(s, " ", ""))
	return t == reverse(t)
}

//go:noinline
func wordHistogram(s string) map[string]int {
	h := map[string]int{}
	for _, w := range strings.Fields(s) {
		h[strings.ToLower(w)]++
	}
	return h
}

type Scorer interface{ Score(string) int }

type lenScorer struct{}
type vowelScorer struct{ weight int }

//go:noinline
func (lenScorer) Score(s string) int { return len(s) }

//go:noinline
func (v vowelScorer) Score(s string) int { return v.weight * countVowels(s) }

//go:noinline
func best(scorers []Scorer, s string) int {
	m := 0
	for _, sc := range scorers {
		if x := sc.Score(s); x > m {
			m = x
		}
	}
	return m
}

func main() {
	s := "reverse engineering never odd or even"
	if len(os.Args) > 1 {
		s = strings.Join(os.Args[1:], " ")
	}
	fmt.Printf("rev=%q\n", reverse(s))
	fmt.Printf("vowels=%d palindrome=%v\n", countVowels(s), isPalindrome(s))
	h := wordHistogram(s)
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s=%d\n", k, h[k])
	}
	fmt.Printf("best=%d\n", best([]Scorer{lenScorer{}, vowelScorer{3}}, s))
}
