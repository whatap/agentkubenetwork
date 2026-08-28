//go:build linux

package collector

//go:generate go tool bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror" network bpf/flow.bpf.c
