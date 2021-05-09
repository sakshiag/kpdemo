package encrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/kp-lab/kpdemo/client"
	"github.com/kp-lab/kpdemo/config"

	"go.uber.org/zap"
)

// EncryptObject encrypts the given object using AES GCM 256 encryption
// It returns the encrypted value as a string or it returns an error
func EncryptObject(ctx context.Context, data []byte, logger *zap.Logger, cfg config.Configuration) (retData string, err error) {

	var sEncNewDek, unEncNewDek, sEncWDek, keybyte []byte

	sEncNewDek, sEncWDek, err = Encryption(ctx, logger, cfg)
	if err != nil {
		logger.Error(err.Error())
		return "", err
	}

	unEncNewDek, err = b64.StdEncoding.DecodeString(string(sEncNewDek))
	keybyte = unEncNewDek
	kmsSecret := string(sEncWDek)
	retData, err = getretData(data, keybyte, kmsSecret)
	if err != nil {
		logger.Error(err.Error())
		return
	}

	return retData, nil
}

func Encryption(ctx context.Context, logger *zap.Logger, cfg config.Configuration) ([]byte, []byte, error) {
	var sEncNewDek, sEncWDek []byte
	var err error

	crn := strings.Split(cfg.ROOTKEYCRN, ":")

	kpClient, err := client.NewKeyProtectClient(ctx, logger, &cfg, crn[7])
	// Generate the del and wrapped dek
	sEncNewDek, sEncWDek, err = kpClient.WrapCreateDEK(ctx, crn[9], nil)

	if err != nil {
		return nil, nil, err
	}

	return sEncNewDek, sEncWDek, nil
}

func getretData(data, keybyte []byte, kmsSecret string) (retData string, err error) {

	plaintext := data
	var block cipher.Block
	block, err = aes.NewCipher(keybyte)
	if err != nil {
		err = fmt.Errorf("Create Cipher block failed: ('%v'), with keybyte : ('%v')", err, keybyte)
		return "", nil
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		err = fmt.Errorf("Create CGM block failed: ('%v')", err)
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	textData := hex.EncodeToString(ciphertext)
	nonceData := hex.EncodeToString(nonce)
	retData = kmsSecret + ":" + nonceData + ":" + textData

	return retData, nil

}
