package onepass

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"path"
)

type keyJson struct {
	Data       string `json:"data"`
	Validation string `json:"validation"`
	Identifier string `json:"identifier"`
	Level      string `json:"level"`
	Iterations int    `json:"iterations"`
}

type keychainJson struct {
	KeyList []keyJson `json:"list"`
}

type Keychain struct {
	keys []*EncryptionKey
}

func (k *Keychain) Unlock(pass string) error {
	var err error

	for i, key := range k.keys {
		log.Debugf("Unlocking key %d...\n", i)
		err = key.Unlock(pass)
		if err != nil {
			log.Errorf("Error unlocking key %d (%s)", i, key.level)
			return err
		}
	}

	return nil
}

func LoadKeychain(rootPath string) (*Keychain, error) {
	keysPath := path.Join(rootPath, "data", "default", "encryptionKeys.js")
	file, err := ioutil.ReadFile(keysPath)
	if err != nil {
		log.Debugln("Error reading keys file")
		return nil, err
	}

	var loadedKeychain keychainJson
	err = json.Unmarshal(file, &loadedKeychain)
	if err != nil {
		log.Debugln("Error loading keys JSON")
		return nil, err
	}

	// Verify that we have at least one key (since Go's JSON decoder
	// doesn't error on a bad field).
	if len(loadedKeychain.KeyList) < 1 {
		return nil, errors.New("didn't find any keys")
	}

	keys := make([]*EncryptionKey, len(loadedKeychain.KeyList))
	log.Printf("Found %d keys", len(loadedKeychain.KeyList))

	for i, k := range loadedKeychain.KeyList {
		keys[i], err = NewEncryptionKey(&k)
		if err != nil {
			log.Debugf("Error loading key %d (%s)", i, k.Level)
			return nil, err
		}

		log.Infof(keys[i].Describe())
	}

	ret := &Keychain{
		keys: keys,
	}
	return ret, nil
}
