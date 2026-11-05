#!/bin/sh

algo=vta	# most precise, but also most computationally expensive; [static, cha, rta, vta]

callgraph -algo $algo -format=digraph *.go | digraph nodes | sort -u # get the set of all nodes (called functions)

#| grep -E "golang.org/x/crypto"
