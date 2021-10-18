package main

import (
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type encryptModel struct {

	key 	 string `json:"key"`
	data     string `json:"data"`
}

type decryptModel struct {
	id     string `json:"id"`
	key 	string `json:"key"`
}

func main() {


	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	

	//Decrypt the data
	e.POST("/decrypt", func(c echo.Context) error {


		// Start the server
		sh := shell.NewShell("localhost:5001")

		getDecrypt := new(decryptModel)
		keyWord := []byte(getDecrypt.key)

		//To be able to output the result we need to have the local directory
		localdir, err := os.Getwd()

		if err != nil{
			fmt.Printf("error: %s", err)
		}

		// after being sure that we have the local directory and server
		// we can start retrieving the hash, using Get function 
		decId := getDecrypt.id
		id := sh.Get(decId, localdir) // func (s *Shell) Get(hash, outdir string) error

		// get function return an error so if the id is not null then we need to print the error
		if id != nil{
			fmt.Printf("error: %s", id)
		}
	
		// ReadFile reads the file named by filename and returns the contents.
		result,readerr := ioutil.ReadFile(decId) // func ReadFile(filename string) ([]byte, error)
	
		if readerr != nil{
			fmt.Printf("error: %s", readerr)
		}
	
		// we have the result as slice of bytes so we need to convert it to string
		finalResult := string(result)
	
		decryptedInput := decrypt(keyWord, finalResult)

		return c.JSON(http.StatusOK, decryptedInput)

	})


	//Encrypt the data 
	e.POST("/encrypt", func(c echo.Context) error {

		encryptDataModel := new(encryptModel)

		key := []byte(encryptDataModel.key)

		encryptedData := encrypt(key, encryptDataModel.data)

		//start the shell
		sh := shell.NewShell("localhost:5001")
		// store a string in IPFS 
		id, addErr := sh.Add(strings.NewReader(encryptedData))
		if addErr != nil {
			fmt.Printf("error: %s", addErr)
		}

		return c.JSON(http.StatusOK, id)

	})

	// Start server
	e.Logger.Fatal(e.Start(":1323"))

}


// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	// key := []byte(keyText)
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}