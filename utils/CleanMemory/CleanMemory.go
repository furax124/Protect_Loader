package CleanMemory

import (
	"log"
)

func ZeroizeMemory(data []byte) {
	log.Printf("[*] Zeroizing memory - Size: %d bytes", len(data))
	for i := range data {
		data[i] = 0
	}
	log.Printf("[+] Memory zeroized successfully")
	log.Println("[*] ZeroizeMemory function executed")
}
