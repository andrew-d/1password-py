package onepass

import (
    "crypto/md5"
)

// NOTE: PBKDF1_MD5("password", '\x00' * 16, 1, 32) should result in:
//      c73027dc71cb87ccbfc1787e8db7386b60f88199755b4bfe45df51372fc7062c
func PBKDF1_MD5(password, salt []byte, iter, keyLen int) []byte {
    // This is a stupid function for doing PBKDF1.
    // TODO: Optimize to not store everything
    var prev, curr, allData []byte
    var i int

    hash := md5.New()
    for len(allData) < keyLen {
        curr = append(prev, password...)
        curr = append(curr, salt...)

        // Repeatedly hash the current value.
        for i = 0; i < iter; i++ {
            hash.Reset()
            hash.Write(curr)
            curr = hash.Sum(nil)
        }

        // Save the hash value from this iteration.
        prev = curr

        // Save the hash value.
        allData = append(allData, curr...)
    }

    // Grab the requested bytes from allData.
    return allData[len(allData)-keyLen:]
}
