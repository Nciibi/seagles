package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Nciibi/seagles/db"
)

func main() {
	h := db.Connect(os.Args[1], 5, 2, 5*time.Minute)
	for i := 1; i <= 3; i++ {
		fmt.Printf("--- run %d ---\n", i)
		if err := db.RunMigrations(h); err != nil {
			fmt.Println("MIGRATION FAILED:", err)
			os.Exit(1)
		}
	}
	fmt.Println("ALL RUNS OK")
}
