package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/martian/log"
	"github.com/graydance/go-kit/core/logx"
)

const ioRead = 1  // 读取
const ioWrite = 2 // 写入

// IoFile IO文件
type IoFile struct {
	Io       int    `json:"io"`       // 1--读取文件  2--写入文件
	FileName string `json:"fileName"` // 读取的文件名
	Content  string `json:"content"`  // 写入文件的内容
	Key      string `json:"key"`      // 秘钥
}

func execFile(req IoFile) (string, error) {
	resp := ""

	// 如果io操作为写入 且 内容为空 直接返回错误
	if req.Io == ioWrite && len(req.Content) == 0 {
		log.Errorf("operate invalid")
		return resp, errors.New("operate invalid")
	}

	// io操作为写入的
	// 指定的文件存在. 读取里面的内容(解密).追加内容
	// 指定的文件不存在. 创建文件.追加内容
	if req.Io == ioWrite {
		file, err := os.OpenFile(req.FileName, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Errorf("open file failed,err:%s", err.Error())
			//log.Errorf("open file failed,err:%s", err.Error())
			return resp, errors.New("inner errors")
		}
		defer file.Close()

		file.Seek(0, 0)

		fileContent, err := io.ReadAll(file)
		if err != nil {
			log.Errorf("read file failed,err:%s", err.Error())
			return resp, errors.New("inner errors")
		}

		// 如果文件有内容,将内容解密
		if len(fileContent) > 0 {
			decryptContent, err := decrypt(fileContent, []byte(req.Key))
			if err != nil {
				fileContent = make([]byte, 0)
			}
			fileContent = decryptContent
		}

		// 拼接需要加密的内容
		encryptContent := make([]byte, 0)
		if len(fileContent) == 0 {
			encryptContent = []byte(req.Content)
		}

		if len(fileContent) != 0 {
			fileContent = append(fileContent, req.Content...)
			encryptContent = fileContent

			// 覆盖旧文件
			file.Close()
			file, err = os.OpenFile(req.FileName, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
			if err != nil {
				log.Errorf("open file failed,err:%s", err.Error())
				return resp, errors.New("inner errors")
			}
			defer file.Close()
		}

		// 将内容加密
		result, err := encrypt(encryptContent, []byte(req.Key))
		if err != nil {
			log.Errorf("encry failed,err:%s", err.Error())
		}

		//将加密内容存入文件
		writeCount, err := file.Write(result)
		if err != nil {
			log.Errorf("write file failed,err:%s", err.Error())
			return resp, err
		}

		logx.Infof("write count :===%d", writeCount)

		return resp, nil
	}

	// io操作为读取的
	// 指定的文件存在. 读取里面的内容
	// 指定的文件不存在. 报错
	if req.Io == ioRead {
		// 读取操作,如果key不存在就报错
		if len(req.Key) == 0 {
			return resp, errors.New("read file key not found")
		}

		file, err := os.OpenFile(req.FileName, os.O_CREATE, 0644)
		if err != nil {
			log.Errorf("open file failed,err:%s", err.Error())
			return resp, errors.New("inner errors")
		}
		defer file.Close()

		file.Seek(0, 0)

		fileContent, err := io.ReadAll(file)
		if err != nil {
			log.Errorf("read file failed,err:%s", err.Error())
			return resp, errors.New("inner errors")
		}
		result, err := decrypt(fileContent, []byte(req.Key))
		if err != nil {
			log.Errorf("decryp failed,err:%s", err.Error())
			return resp, errors.New("inner errors")
		}

		logx.Infof("result:====%s", string(result))
	}

	return resp, nil
}

// block iv  block是key iv 长度为 aes.BlockSize 的随机内容.

// 加密函数
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建一个与明文长度相同的缓冲区，并在前面加上 IV
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 使用 CFB 模式加密
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// 解密函数
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("密文太短")
	}

	// 提取 IV
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// 使用 CBC 模式解密
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func main() {
	req := IoFile{
		Io:       ioWrite,
		FileName: "test.txt",
		Content:  "this is first file",
		Key:      "heiheieiheieihei",
	}

	_, err := execFile(req)
	if err != nil {
		logx.Infof("exec file failed,err:%s", err.Error())
		return
	}

	req = IoFile{
		Io:       ioRead,
		FileName: "test.txt",
		//Content:  "this is first file",
		Key: "heiheieiheieihei",
	}

	_, err = execFile(req)
	if err != nil {
		logx.Infof("exec file failed,err:%s", err.Error())
		return
	}

}
