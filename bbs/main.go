package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"

	ml "github.com/IBM/mathlib"
	"github.com/hyperledger/aries-bbs-go/bbs"
)

func main() {
	// 初始化BBS签名方案
	curve := ml.Curves[ml.BLS12_381_BBS]
	bbsScheme := bbs.New(curve)
	bbsLib := bbs.NewBBSLib(curve)

	// 1. 生成颁发者和持有者密钥对
	issuer1PubKey, issuer1PrivKey := generateKeyPair(bbsLib, "颁发者1")
	issuer2PubKey, issuer2PrivKey := generateKeyPair(bbsLib, "颁发者2")
	holderPubKey, holderPrivKey := generateKeyPair(bbsLib, "持有者")

	// 打印颁发者公钥信息
	printKeyInfo("颁发者1", issuer1PubKey)
	printKeyInfo("颁发者2", issuer2PubKey)

	// 2. 构造VC声明
	vcClaims1 := [][]byte{
		[]byte("enName: Doris"),
		[]byte("address: 16/F Shek Mun"),
		[]byte("driverID: abcdef123456789"),
	}
	vcClaims2 := [][]byte{
		[]byte("enName: Doris"),
		[]byte("address: 16/F Shek Mun"),
		[]byte("birthDate: 1990/01/01"),
	}

	printMessages("原始VC1声明", vcClaims1)
	printMessages("原始VC2声明", vcClaims2)

	// 3. 颁发者对VC进行签名
	signature1, err := signMessages(bbsScheme, vcClaims1, issuer1PrivKey)
	if err != nil {
		log.Fatalf("发证方签名失败: %v", err)
	}
	printSignatureInfo("VC1签名", signature1)

	signature2, err := signMessages(bbsScheme, vcClaims2, issuer2PrivKey)
	if err != nil {
		log.Fatalf("发证方签名失败: %v", err)
	}
	printSignatureInfo("VC2签名", signature2)

	// 4. 选择性披露
	revealedIndexes1 := []int{0, 2} // 披露姓名和国籍
	revealedIndexes2 := []int{0, 2} // 披露姓名和国籍
	nonce := []byte("nonce")

	printDisclosureInfo(vcClaims1, revealedIndexes1, nonce)
	printDisclosureInfo(vcClaims2, revealedIndexes2, nonce)

	// 生成选择性披露证明
	issuer1PubKeyBytes, err := issuer1PubKey.Marshal()
	if err != nil {
		log.Fatalf("序列化颁发者公钥1失败: %v", err)
	}
	issuer2PubKeyBytes, err := issuer2PubKey.Marshal()
	if err != nil {
		log.Fatalf("序列化颁发者公钥2失败: %v", err)
	}

	proof1, err := bbsScheme.DeriveProof(vcClaims1, signature1, nonce, issuer1PubKeyBytes, revealedIndexes1)
	if err != nil {
		log.Fatalf("生成选择性披露1证明失败: %v", err)
	}

	printProofInfo("选择性披露证明1", proof1)

	proof2, err := bbsScheme.DeriveProof(vcClaims2, signature2, nonce, issuer2PubKeyBytes, revealedIndexes2)
	if err != nil {
		log.Fatalf("生成选择性披露证明2失败: %v", err)
	}

	printProofInfo("选择性披露证明2", proof2)

	// 5. 验证过程
	// 5.1 首先验证持有者签名
	disclosedClaims1 := getDisclosedMessages(vcClaims1, revealedIndexes1)
	disclosedClaims2 := getDisclosedMessages(vcClaims2, revealedIndexes2)
	// 合并两个二维字节切片
	mergedSlice := append(disclosedClaims1, disclosedClaims2...)
	holderSignature, err := signMessages(bbsScheme, mergedSlice, holderPrivKey)
	if err != nil {
		log.Fatalf("持有者签名选择性披露失败: %v", err)
	}
	printSignatureInfo("持有者选择性披露签名", holderSignature)
	err = verifyHolderSignature(bbsScheme, mergedSlice, holderPubKey, holderSignature)
	if err != nil {
		log.Fatalf("验证持有者签名失败: %v", err)
	}
	// 5.2 验证选择性披露证明
	verifyDisclosureProof(bbsScheme, disclosedClaims1, proof1, nonce, issuer1PubKeyBytes)
	verifyDisclosureProof(bbsScheme, disclosedClaims2, proof2, nonce, issuer2PubKeyBytes)
}

// generateKeyPair 生成密钥对
func generateKeyPair(bbsLib *bbs.BBSLib, owner string) (*bbs.PublicKey, *bbs.PrivateKey) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		log.Fatalf("%s随机种子生成失败: %v", owner, err)
	}

	pubKey, privKey, err := bbsLib.GenerateKeyPair(sha256.New, seed)
	if err != nil {
		log.Fatalf("%s密钥对生成失败: %v", owner, err)
	}

	return pubKey, privKey
}

// printKeyInfo 打印公钥信息
func printKeyInfo(owner string, pubKey *bbs.PublicKey) {
	fmt.Printf("\n=== %s公钥 ===\n", owner)
	fmt.Printf("公钥结构: %+v\n", pubKey)

	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		log.Fatalf("序列化%s公钥失败: %v", owner, err)
	}

	fmt.Printf("公钥(HEX): %x\n", pubKeyBytes)
	fmt.Printf("公钥(Base64): %s\n", base64.StdEncoding.EncodeToString(pubKeyBytes))
}

// printMessages 打印消息内容
func printMessages(title string, messages [][]byte) {
	fmt.Printf("\n=== %s ===\n", title)
	for i, msg := range messages {
		fmt.Printf("消息 %d: %s\n", i, msg)
	}
}

// signMessages 对消息进行签名
func signMessages(bbsScheme *bbs.BBSG2Pub, messages [][]byte, privKey *bbs.PrivateKey) (signature []byte, err error) {
	privKeyBytes, err := privKey.Marshal()
	if err != nil {
		log.Fatalf("序列化私钥失败: %v", err)
		return
	}
	signature, err = bbsScheme.Sign(messages, privKeyBytes)
	if err != nil {
		log.Fatalf("消息签名失败: %v", err)
	}
	return
}

// printSignatureInfo 打印签名信息
func printSignatureInfo(title string, signature []byte) {
	fmt.Printf("\n=== %s ===\n", title)
	fmt.Printf("签名(HEX): %x\n", signature)
	fmt.Printf("签名(Base64): %s\n", base64.StdEncoding.EncodeToString(signature))
	fmt.Printf("签名长度: %d 字节\n", len(signature))
	fmt.Println("📝 签名成功")
}

// printDisclosureInfo 打印选择性披露信息
func printDisclosureInfo(messages [][]byte, revealedIndexes []int, nonce []byte) {
	fmt.Printf("\n=== 选择性披露 ===\n")
	fmt.Printf("披露的消息索引: %v\n", revealedIndexes)
	for _, idx := range revealedIndexes {
		fmt.Printf("披露的消息 %d: %s\n", idx, messages[idx])
	}
	fmt.Printf("Nonce: %s\n", nonce)
}

// getDisclosedMessages 获取披露的消息
func getDisclosedMessages(messages [][]byte, revealedIndexes []int) [][]byte {
	disclosed := make([][]byte, len(revealedIndexes))
	for i, idx := range revealedIndexes {
		disclosed[i] = messages[idx]
	}
	return disclosed
}

// printProofInfo 打印证明信息
func printProofInfo(title string, proof []byte) {
	fmt.Printf("\n=== %s ===\n", title)
	fmt.Printf("Proof(HEX): %x\n", proof)
	fmt.Printf("Proof(Base64): %s\n", base64.StdEncoding.EncodeToString(proof))
	fmt.Printf("Proof长度: %d 字节\n", len(proof))
	fmt.Println("🔍 选择性披露VP生成成功")
}

// verifyHolderSignature 验证持有者签名
func verifyHolderSignature(bbsScheme *bbs.BBSG2Pub, messages [][]byte, pubKey *bbs.PublicKey, signature []byte) error {
	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		log.Fatalf("序列化持有者公钥失败: %v", err)
		return err
	}
	// 验证持有者签名
	if err := bbsScheme.Verify(messages, signature, pubKeyBytes); err != nil {
		log.Fatalf("持有者签名验证失败: %v", err)
		return err
	}
	return nil
}

// verifyDisclosureProof 验证选择性披露证明
func verifyDisclosureProof(bbsScheme *bbs.BBSG2Pub, messages [][]byte, proof, nonce, pubKeyBytes []byte) {
	fmt.Println("\n=== 验证证明 ===")
	fmt.Println("验证中...")

	if err := bbsScheme.VerifyProof(messages, proof, nonce, pubKeyBytes); err != nil {
		log.Fatalf("证明验证失败: %v", err)
	}

	fmt.Println("✅ 证明验证成功")
}
