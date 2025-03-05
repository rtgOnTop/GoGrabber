package antivm

import (
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type MemStatusEx struct { // Auxiliary struct to retrieve total memory
	dwLength     uint32
	dwMemoryLoad uint32
	ullTotalPhys uint64
	ullAvailPhys uint64
	unused       [5]uint64
}

type WindowsProcess struct { // Windows process structure
	ProcessID       int // PID
	ParentProcessID int
	Exe             string // Cmdline executable (e.g. explorer.exe)
}

func GetProcesses() ([]WindowsProcess, error) { // Get all processes using windows API
	handle, err := windows.CreateToolhelp32Snapshot(0x00000002, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(handle, &entry)
	if err != nil {
		return nil, err
	}

	results := make([]WindowsProcess, 0, 50)
	for {
		results = append(results, NewWindowsProcess(&entry))

		err = windows.Process32Next(handle, &entry)
		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}

			return nil, err
		}
	}
}

// Auxiliary function
func NewWindowsProcess(e *windows.ProcessEntry32) WindowsProcess {
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return WindowsProcess{
		ProcessID:       int(e.ProcessID),
		ParentProcessID: int(e.ParentProcessID),
		Exe:             syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

func CheckCPU() bool {
	if runtime.NumCPU() < 3 {
		return false
	}
	return true

}

func CheckDrivers() bool {
	drivers := []string{
		"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
		"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
		"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
		"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
		"C:\\Windows\\System32\\vboxdisp.dll",
		"C:\\Windows\\System32\\vboxhook.dll",
		"C:\\Windows\\System32\\vboxmrxnp.dll",
		"C:\\Windows\\System32\\vboxogl.dll",
		"C:\\Windows\\System32\\vboxoglarrayspu.dll",
		"C:\\Windows\\System32\\vboxservice.exe",
		"C:\\Windows\\System32\\vboxtray.exe",
		"C:\\Windows\\System32\\VBoxControl.exe",
		"C:\\Windows\\System32\\drivers\\vmmouse.sys",
		"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
		"C:\\Windows\\System32\\drivers\\vmci.sys",
		"C:\\Windows\\System32\\drivers\\vmmemctl.sys",
		"C:\\Windows\\System32\\drivers\\vmmouse.sys",
		"C:\\Windows\\System32\\drivers\\vmrawdsk.sys",
		"C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
	}

	for _, d := range drivers { // Iterate over all drivers to check if they exist
		_, err := os.Stat(d)
		if !os.IsNotExist(err) {
			return true
		}
	}
	return false
}

func GetProc() bool {
	sandbox_processes := []string{`vmsrvc`, `tcpview`, `wireshark`, `visual basic`, `fiddler`,
		`vmware`, `vbox`, `process explorer`, `autoit`, `vboxtray`, `vmtools`,
		`vmrawdsk`, `vmusbmouse`, `vmvss`, `vmscsi`, `vmxnet`, `vmx_svga`,
		`vmmemctl`, `df5serv`, `vboxservice`, `vmhgfs`}
	p, err1 := process.Processes()
	if err1 != nil {
		panic(err1)
	}
	for _, procNames := range sandbox_processes {
		for _, name := range p {
			name, err := name.Name()
			if err == nil && name == procNames {
				return true
			}
		}
	}
	return false
}

func CheckModdedDNS() bool {
	resp, err := http.Get("https://this-is-a-fake-domain.com")
	if err != nil {
		return true
	}
	if resp.StatusCode == 200 {
		return true
	}
	return false

}

func CheckUsers() bool {
	u, _ := user.Current()

	// Some well known sandbox users (could be much better)
	known_usernames := []string{"trans_iso_0", "analysis", "sandbox", "debug4fun", "j.yoroi", "Virtual", "user1", "Cuckoofork", "JujuBox"}
	for _, name := range known_usernames {
		if u.Username == name { // Check if any name match
			return true
		}
	}
	return false
}

func CheckStorage() bool {
	GetDiskFreeSpaceExW := windows.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

	lpTotalNumberOfBytes := int64(0)
	diskret, _, err := GetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("C:\\"))),
		uintptr(0),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(0),
	)
	if diskret == 0 {
		panic(err)
	}

	if int(lpTotalNumberOfBytes) < 68719476736 {
		return true
	}
	return false
}

func GetRam() bool {
	msx := &MemStatusEx{
		dwLength: 64,
	}

	GlobalMemoryStatusEx := windows.NewLazyDLL("kernel32").NewProc("GlobalMemoryStatusEx")
	r1, _, err := GlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(msx)))
	if r1 == 0 {
		panic(err)
	}

	// 4174967296 bytes = 4GB
	if int(msx.ullTotalPhys) < 4174967296 {
		return true
	}
	return false
}

func GetHostname() bool {
	hostname, _ := os.Hostname()
	known_hostnames := []string{"sandbox", "analysis", "vmware", "vbox", "qemu", "virustotal", "cuckoofork"}
	for _, h := range known_hostnames {
		if hostname == h {
			return true
		}
	}
	return false
}

func registryCheck() bool {
	// Run the first registry query
	reg1Cmd := exec.Command("cmd", "/C", `REG QUERY HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000\DriverDesc 2> nul`)
	reg1Cmd.Run()
	// Run the second registry query
	// Open the registry key
	handle, _ := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Disk\Enum`, registry.QUERY_VALUE)
	defer handle.Close()

	// Query the registry value
	regVal, _, _ := handle.GetStringValue("0")

	// Check if the value contains VMware or VBOX
	if strings.Contains(regVal, "VMware") || strings.Contains(regVal, "VBOX") {
		return true
	}
	return false
}
