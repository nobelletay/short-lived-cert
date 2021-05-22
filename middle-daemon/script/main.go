package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Subject to change
// const num_of_cert = 3

func main() {
	fmt.Println("Listening to certificate request...")
	for {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			words := strings.Fields(scanner.Text())
			count, err := strconv.Atoi(words[1])
			check(err)

			domain_name := words[0]
			fmt.Println("Decrypting certificates...")
			main_decrypt(domain_name, count)

			fmt.Println("Building merkle tree and proof...")
			ex, err := os.Executable()
			check(err)
			exPath := filepath.Dir(ex)

			c := exec.Command("python", exPath+"/MDincproof.py", domain_name, strconv.Itoa(count))
			if err := c.Run(); err != nil {
				check(err)
			}
		}

		if scanner.Err() != nil {
			// Handle error.
		}
	}
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}
