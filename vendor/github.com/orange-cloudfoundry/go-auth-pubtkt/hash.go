package pubtkt

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
)

const (
	Hsha1   hashMethod = "sha1"
	Hsha224 hashMethod = "sha224"
	Hsha256 hashMethod = "sha256"
	Hsha384 hashMethod = "sha384"
	Hsha512 hashMethod = "sha512"
)

type hashMethod string

type OpenSSLCreds struct {
	key []byte
	iv  []byte
}

const (
	MethodEcb EncMethod = "ECB"
	MethodCbc EncMethod = "CBC"
)

type EncMethod string

type OpenSSL struct {
	openSSLSaltHeader string
}

func NewOpenSSL() *OpenSSL {
	return &OpenSSL{
		openSSLSaltHeader: "Salted__", // OpenSSL salt is always this string + 8 bytes of actual salt
	}
}

// Decrypt string that was encrypted using OpenSSL and AES-256-CBC or AES-256-ECB
func (o OpenSSL) DecryptString(passphrase, encryptedBase64String string, method EncMethod) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedBase64String)
	if err != nil {
		return nil, err
	}
	saltHeader := data[:aes.BlockSize]
	salt := saltHeader[8:]
	isSalted := true
	if string(saltHeader[:8]) != o.openSSLSaltHeader {
		salt = nil
		isSalted = false
	}
	creds, err := o.extractOpenSSLCreds([]byte(passphrase), salt)
	if err != nil {
		return nil, err
	}
	if method == MethodCbc {
		return o.decryptCbc(creds.key, creds.iv, data, isSalted)
	}
	return o.decryptEcb(creds.key, data, isSalted)
}
func (o OpenSSL) decryptEcb(key, data []byte, isSalted bool) ([]byte, error) {
	cipherKey, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dest := make([]byte, len(data))
	decrypter := NewECBDecrypter(cipherKey)
	decrypter.CryptBlocks(dest, data)
	startDec := decrypter.BlockSize()
	if !isSalted {
		startDec = 0
	}
	out, err := pkcs7Unpad(dest[startDec:], decrypter.BlockSize())
	if out == nil {
		return nil, err
	}
	return out, nil
}
func (o OpenSSL) decryptCbc(key, iv, data []byte, isSalted bool) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("bad blocksize(%v), aes.BlockSize = %v\n", len(data), aes.BlockSize)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(c, iv)
	startDec := cbc.BlockSize()
	if !isSalted {
		startDec = 0
	}
	cbc.CryptBlocks(data[startDec:], data[startDec:])

	out, err := pkcs7Unpad(data[startDec:], aes.BlockSize)
	if out == nil {
		return nil, err
	}
	return out, nil
}

// openSSLEvpBytesToKey follows the OpenSSL (undocumented?) convention for extracting the key and IV from passphrase.
// It uses the EVP_BytesToKey() method which is basically:
// D_i = HASH^count(D_(i-1) || password || salt) where || denotes concatentaion, until there are sufficient bytes available
// 48 bytes since we're expecting to handle AES-256, 32bytes for a key and 16bytes for the IV
func (o OpenSSL) extractOpenSSLCreds(password, salt []byte) (OpenSSLCreds, error) {
	m := make([]byte, 48)
	prev := []byte{}
	for i := 0; i < 3; i++ {
		prev = o.hash(prev, password, salt)
		copy(m[i*16:], prev)
	}
	return OpenSSLCreds{key: m[:32], iv: m[32:]}, nil
}

func (o OpenSSL) hash(prev, password, salt []byte) []byte {
	a := make([]byte, len(prev)+len(password)+len(salt))
	copy(a, prev)
	copy(a[len(prev):], password)
	copy(a[len(prev)+len(password):], salt)
	return o.md5sum(a)
}

func (o OpenSSL) md5sum(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padlen], nil
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int {
	return x.blockSize
}

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func FindHash(hashStr string) (hash.Hash, crypto.Hash, error) {

	switch hashMethod(hashStr) {
	case Hsha1:
		return sha1.New(), crypto.SHA1, nil
	case Hsha224:
		return sha256.New224(), crypto.SHA224, nil
	case Hsha256:
		return sha256.New(), crypto.SHA256, nil
	case Hsha384:
		return sha512.New384(), crypto.SHA384, nil
	case Hsha512:
		return sha512.New(), crypto.SHA512, nil
	default:
		return nil, crypto.Hash(0), fmt.Errorf("Hash %s is not a sha hash", hashStr)
	}
}

func BauthDecrypt(bauth, keyStr string) (string, error) {
	key := []byte(keyStr)
	ciphertext, _ := base64.StdEncoding.DecodeString(bauth)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return string(bytes.Trim(ciphertext, "\x00")), nil
}
