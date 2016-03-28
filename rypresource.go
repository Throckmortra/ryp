package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/emicklei/go-restful"
)

type Ryp struct {
	Input string `json:"input"`
	Key   string `json:"key"`
	Type  string `json:"type"`
}

type RypOutput struct {
	Encrypted []byte `json:"encrypted"`
}

type Deryp struct {
	Input []byte `json:"encrypted"`
	Key   string `json:"key"`
}

type DerypOutput struct {
	Decrypted string `json:"decrypted"`
}

type Random struct {
	RanStr string `json:"random"`
}

type RypResource struct{}

var globalKey, _ = base64.StdEncoding.DecodeString("BkosO/uLGUUcYDeA23I9y0TIbLI+iKid7AJRIgj5Amc=")

func (u RypResource) Register(container *restful.Container) {
	ws := new(restful.WebService)

	ws.
		Path("/").
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)

	ws.Route(ws.GET("/random").To(u.random).
		Operation("random"))

	ws.Route(ws.POST("").To(u.crypt).
		Operation("crypt").
		Reads(Ryp{}))

	ws.Route(ws.POST("/decrypt").To(u.deryp).
		Operation("deryp").
		Reads(Deryp{}))

	ws.Route(ws.GET("/test").To(u.test).
		Operation("test"))

	container.Add(ws)
}

//random
func (u RypResource) random(request *restful.Request, response *restful.Response) {
	rando := new(Random)
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "#1 "+err.Error())
		return
	}

	sEnc := base64.StdEncoding.EncodeToString(key)
	if err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "#2 "+err.Error())
		return
	}
	rando.RanStr = sEnc
	response.WriteHeaderAndEntity(http.StatusCreated, rando)
}

//crypt
func (u RypResource) crypt(request *restful.Request, response *restful.Response) {
	ryp := new(Ryp)
	err := request.ReadEntity(ryp)

	if err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "#3 "+err.Error())
		return
	}

	key, _ := base64.StdEncoding.DecodeString(ryp.Key)
	ciphertxt, err := encrypt(key, []byte(ryp.Input))
	if err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "#4 "+err.Error())
	}

	respond := new(RypOutput)
	respond.Encrypted = ciphertxt

	response.WriteEntity(respond)
}

//encrypt
func encrypt(key, text []byte) (ciphertext []byte, err error) {

	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(string(text)))

	// iv =  initialization vector
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)

	return
}

//deryp
func (u RypResource) deryp(request *restful.Request, response *restful.Response) {
	dryp := new(Deryp)

	err := request.ReadEntity(dryp)
	if err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "#5 "+err.Error())
		return
	}

	log.Printf("undecoded key string is " + dryp.Key)
	key, err := base64.StdEncoding.DecodeString(dryp.Key)
	if err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "#6 "+err.Error())
		return
	}

	n, err := base64.StdEncoding.Decode(dryp.Input, dryp.Input)

	log.Printf("the input is " + string(dryp.Input) + " this many bytes: " + string(n))

	output, err := decrypt(key, dryp.Input)
	if err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "#7 "+err.Error())
		return
	}

	respond := new(DerypOutput)
	respond.Decrypted = string(output)

	response.WriteEntity(respond)
}

//decrypt
func decrypt(key, ciphertext []byte) (plaintext []byte, err error) {

	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	plaintext = ciphertext

	return
}

//test
func (u RypResource) test(request *restful.Request, response *restful.Response) {

	var ciphertext, plaintext []byte
	var err error

	var key = globalKey
	plaintext = []byte("This is the unecrypted data. Referring to it as plain text.")

	if ciphertext, err = encrypt(key, plaintext); err != nil {
		log.Fatal(err)
	}

	var asdf []byte
	if asdf, err = decrypt(key, ciphertext); err != nil {
		log.Fatal(err)
	}

	respond := new(DerypOutput)
	respond.Decrypted = string(asdf)

	response.WriteEntity(respond)
}
