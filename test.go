package main

import (
    "os"
    "fmt"

    "./onepass-go"
)


func main() {
    k, err := onepass.LoadKeychain(os.Args[1])
    if err != nil {
        fmt.Printf("Error loading keychain: %s\n", err)
        os.Exit(1)
    }

    pwd, err := onepass.GetPass()
    if err != nil {
        fmt.Printf("Error getting password: %s\n", err)
        os.Exit(1)
    }

    err = k.Unlock(pwd)
    if err != nil {
        fmt.Printf("Error unlocking keychain: %s\n", err)
        os.Exit(1)
    }

    fmt.Printf("Successfully unlocked keychain!\n")
}
