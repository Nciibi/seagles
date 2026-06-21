package main

import (
	"fmt"
	"log"

	"github.com/yourusername/seagles/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Println("seagles starting...")
	_ = cfg // to avoid unused variable warning if not printed
}
