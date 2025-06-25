package CleanMemory

import (
	"log"
)
//garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func ZeroizeMemory(data []byte) {
	log.Printf("[*] Zeroizing memory - Size: %d bytes", len(data))
	for i := range data {
		data[i] = 0
	}
	log.Printf("[+] Memory zeroized successfully")
	log.Println("[*] ZeroizeMemory function executed")
}
