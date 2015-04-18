package onepass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"

	"code.google.com/p/go.crypto/pbkdf2"

	"fmt"
)

type EncryptionKey struct {
	data       *SaltedString
	validation []byte
	identifier string
	level      string
	iterations int
	unlocked   bool

	// Only valid if unlocked
	key []byte
}

func (k *EncryptionKey) Describe() string {
	return fmt.Sprintf("%s: %x (%d) / %x (%d)",
		k.identifier,
		k.data.Data[0:10],
		len(k.data.Data),
		k.validation[0:10],
		len(k.validation),
	)
}

func (k *EncryptionKey) IsUnlocked() bool {
	return k.unlocked
}

func (k *EncryptionKey) Unlock(password string) error {
	// Trying to unlock twice is a logic error.
	if k.unlocked {
		panic("can't unlock twice")
	}

	// Generate 32 bytes - 16 for AES key, 16 for the IV
	keys := pbkdf2.Key([]byte(password), k.data.Salt, k.iterations, 32, sha1.New)
	key, iv := keys[:16], keys[16:]

	// Try decrypting data with generated key and IV
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	possible_key := make([]byte, len(k.data.Data))
	mode.CryptBlocks(possible_key, k.data.Data)

	// We can validate whether this is correct by trying to decrypt the
	// validation we're given with this key.  If it matches, then we can
	// assume that the given password is correct.
	decrypted_validation := make([]byte, len(k.validation))
	decrypted_validation, err = k.decryptItem(decrypted_validation, k.validation, possible_key)

	log.Printf("%x", decrypted_validation[0:20])
	log.Printf("validation = %x, key = %x", decrypted_validation[len(decrypted_validation)-20:], possible_key[len(possible_key)-20:])
	if !bytes.Equal(decrypted_validation, possible_key) {
		return InvalidPassword
	}

	// If we get here, all is good!
	k.key = possible_key
	k.unlocked = true
	return nil
}

func (k *EncryptionKey) DecryptItem(dst, src []byte) ([]byte, error) {
	return k.decryptItem(dst, src, k.key)
}

func (k *EncryptionKey) decryptItem(out, data, key []byte) ([]byte, error) {
	sstr, err := NewSaltedString(data)
	if err != nil {
		return nil, err
	}

	// If the value is salted, we PBKDF1 it, otherwise, just calculate the
	// MD5 hash.
	var cipher_key, iv []byte
	if sstr.IsSalted {
		keys := PBKDF1_MD5(key, sstr.Salt, 1, 32)
		cipher_key, iv = keys[:16], keys[16:]
	} else {
		hash := md5.New()
		hash.Write(key)
		cipher_key = hash.Sum(nil)
		iv = defaultIV
	}

	block, err := aes.NewCipher(cipher_key)
	if err != nil {
		return nil, err
	}

	out = out[0:len(sstr.Data)]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(out, sstr.Data)
	return out, nil
}

func NewEncryptionKey(keyData *keyJson) (*EncryptionKey, error) {
	// Iterations are always at least 1000
	iter := keyData.Iterations
	if iter < 1000 {
		iter = 1000
	}

	// Create salted string.
	sstr, err := NewSaltedString([]byte(keyData.Data))
	if err != nil {
		return nil, err
	}

	// Make the encryption key structure.
	// validation := bytes.Trim([]byte(keyData.Validation), "\x00")
	validation := []byte(keyData.Validation)
	ret := &EncryptionKey{
		data:       sstr,
		validation: validation,
		identifier: keyData.Identifier,
		level:      keyData.Level,
		iterations: iter,
		unlocked:   false,
	}

	return ret, nil
}
