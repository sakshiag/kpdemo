package decrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"

	b64 "encoding/base64"

	"github.com/kp-lab/kpdemo/client"
	"github.com/kp-lab/kpdemo/config"
	"go.uber.org/zap"
)

// DecryptObject decrypts the given string using AES GCM 256 decryption
// Decrypt is designed to decrypt values that were encrypted using Encrypt
// It returns the decrypted value as a string or it returns an error
// encrypted data string is in the form "secret.nonceData.textData"
func DecryptObject(ctx context.Context, data string, logger zap.Logger, cfg config.Configuration) (plaindata string, err error) {

	var keybyte []byte
	encryptData := strings.Split(data, ":")
	wDek := encryptData[0]
	nonceData := encryptData[1]
	textData := encryptData[2]

	logger.Info("Calling Decrytion", zap.String("MethodName:", "Decryption"))

	keybyte, err = Decryption(ctx, []byte(wDek), cfg, logger)
	if err != nil {
		return "", err
	}

	plaindata, err = getPlainData(keybyte, textData, nonceData)
	if err != nil {
		logger.Error(err.Error())
		return "", err
	}

	return plaindata, nil
}

// Decryption perform decryption
func Decryption(ctx context.Context, wDek []byte, cfg config.Configuration, logger zap.Logger) ([]byte, error) {
	var dek, keybyte []byte
	var err error

	crn := strings.Split(cfg.ROOTKEYCRN, ":")

	kpClient, err := client.NewKeyProtectClient(ctx, &logger, &cfg, crn[7])
	dek, err = kpClient.Unwrap(ctx, crn[9], wDek, nil)

	if err != nil {
		return nil, err
	}

	keybyte, err = b64.StdEncoding.DecodeString(string(dek))
	if err != nil {
		return nil, err
	}
	return keybyte, nil

}

func getPlainData(keybyte []byte, textData, nonceData string) (plaindata string, err error) {

	var ciphertext []byte
	ciphertext, err = hex.DecodeString(textData)
	if err != nil {
		return "", err
	}

	var nonce []byte
	nonce, err = hex.DecodeString(nonceData)
	if err != nil {
		return "", err
	}

	var block cipher.Block
	block, err = aes.NewCipher(keybyte)
	if err != nil {
		return "", err
	}

	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	var plaintext []byte
	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	plaindata = string(plaintext)
	return plaindata, nil
}
