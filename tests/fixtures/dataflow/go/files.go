package main

import "os"

func readUpload(fileName string) ([]byte, error) {
	return os.ReadFile("/srv/uploads/" + fileName)
}
