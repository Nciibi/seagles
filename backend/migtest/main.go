package main

import (
	"fmt"
	"os"

	"github.com/Nciibi/seagles/db"
)

func main() {
	h, err := db.Connect(os.Args[1], 5, 2, 60000000000)
	if err != nil {
		fmt.Println("connect error:", err)
		os.Exit(1)
	}
	if err := db.RunMigrations(h); err != nil {
		fmt.Println("MIGRATION FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("MIGRATIONS OK")
}
