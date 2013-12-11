package onepass

import (
    "errors"
    "os"
    "syscall"

    "code.google.com/p/go.crypto/ssh/terminal"
    "github.com/andrew-d/go-nicelog"
)

var log = nicelog.New(os.Stderr, "", nicelog.LdefaultFlags)

func SetLogLevel(level int) {
    log.SetLevelFilter(level)
}

func GetPass() (string, error) {
    fd := syscall.Stdout

    // If this is not a terminal, then it's an error.
    if !terminal.IsTerminal(fd) {
        return "", errors.New("not a terminal")
    }

    // Print the prompt.
    os.Stdout.Write([]byte("Password: "))
    os.Stdout.Sync()

    pass, err := terminal.ReadPassword(fd)
    os.Stdout.Write([]byte{'\n'})
    if err != nil {
        return "", err
    }

    return string(pass), nil
}
