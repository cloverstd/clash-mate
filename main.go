package main

import (
	"github.com/cloverstd/clash-mate/mate"
)

func main() {
	s := mate.NewServer()
	s.Start(9999)
}
