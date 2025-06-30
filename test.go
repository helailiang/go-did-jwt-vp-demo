package main

//
//import (
//	"crypto/ed25519"
//	"crypto/rand"
//	"crypto/sha256"
//	"encoding/base64"
//	"encoding/json"
//	"fmt"
//	"strings"
//	"time"
//
//	"context"
//
//	"github.com/lestrrat-go/jwx/v2/jwa"
//	"github.com/lestrrat-go/jwx/v2/jwk"
//	"github.com/lestrrat-go/jwx/v2/jws"
//)
//
//// 生成 Disclosure（盐 + 键 + 值 → base64url）
//func createDisclosure(key string, value interface{}) (string, string, error) {
//	salt := make([]byte, 16)
//	_, err := rand.Read(salt)
//	if err != nil {
//		return "", "", err
//	}
//	disclosure := []interface{}{base64.RawURLEncoding.EncodeToString(salt), key, value}
//	jsonBytes, err := json.Marshal(disclosure)
//	if err != nil {
//		return "", "", err
//	}
//	encoded := base64.RawURLEncoding.EncodeToString(jsonBytes)
//	// 计算 disclosure 的 digest（sha256）
//	digest := sha256.Sum256([]byte(encoded))
//	digestB64 := base64.RawURLEncoding.EncodeToString(digest[:])
//	return encoded, digestB64, nil
//}
//
//func main() {
//	// 1. 构造 VC claims (原始完整数据)
//	vcSubjectSource := map[string]interface{}{
//		"id":      "did:example:subject",
//		"name":    "张三",
//		"age":     28,
//		"address": "北京市朝阳区",
//		"gender":  "Female",
//	}
//
//	// 2. 生成 Ed25519 JWK
//	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
//	jwkKey, _ := jwk.FromRaw(privKey)
//	jwkKey.Set(jwk.KeyIDKey, "issuer-key")
//	jwkKey.Set(jwk.AlgorithmKey, jwa.EdDSA)
//
//	// =================== Issuer 流程: 生成所有 Disclosures ===================
//	// 3. 定义所有可披露字段，并生成其 Disclosures 和 Digests
//	vcPayloadSubject := make(map[string]interface{})
//	for k, v := range vcSubjectSource {
//		vcPayloadSubject[k] = v
//	}
//	possibleDiscloseKeys := []string{"name", "age", "address"}
//	allDisclosures := make(map[string]string)
//	var sdDigests []string
//	for _, key := range possibleDiscloseKeys {
//		val := vcPayloadSubject[key]
//		disclosure, digest, _ := createDisclosure(key, val)
//		allDisclosures[key] = disclosure
//		sdDigests = append(sdDigests, digest)
//		delete(vcPayloadSubject, key)
//	}
//	vcPayloadSubject["_sd"] = sdDigests
//
//	// 4. 构造用于签名的 VC
//	vcForSigning := map[string]interface{}{
//		"@context": []interface{}{
//			"https://www.w3.org/2018/credentials/v1",
//		},
//		"id":                "https://example.edu/credentials/1872",
//		"type":              []interface{}{"VerifiableCredential"},
//		"issuer":            "did:example:issuer",
//		"issuanceDate":      time.Now().Format(time.RFC3339),
//		"credentialSubject": vcPayloadSubject,
//	}
//
//	// 4.1 将公钥嵌入 VC
//	pubJWK, _ := jwkKey.PublicKey()
//	pubJWKMap, _ := pubJWK.AsMap(context.Background())
//	vcForSigning["cnf"] = map[string]interface{}{"jwk": pubJWKMap}
//	payload, _ := json.Marshal(vcForSigning)
//
//	// 5. 签名
//	var signer ed25519.PrivateKey
//	_ = jwkKey.Raw(&signer)
//	signedJWT, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA, signer))
//	if err != nil {
//		panic(err)
//	}
//
//	// =================== Holder 流程: 选择性披露 ===================
//	// 6. Holder 决定只披露 name 和 address
//	keysToPresent := []string{"name", "address"}
//	disclosuresToPresent := []string{}
//	for _, key := range keysToPresent {
//		if disclosure, ok := allDisclosures[key]; ok {
//			disclosuresToPresent = append(disclosuresToPresent, disclosure)
//		}
//	}
//
//	// 7. Holder 组合最终的 SD-JWT
//	sdjwt := string(signedJWT) + "~" + strings.Join(disclosuresToPresent, "~")
//	fmt.Println("🔐 SD-JWT (只披露 name 和 address):")
//	fmt.Println(sdjwt)
//
//	// ======== Verifier 流程 ========
//	fmt.Println("\n🔍 开始验证 SD-JWT...")
//
//	parts := strings.Split(sdjwt, "~")
//	signedPart := parts[0]
//	disclosuresToVerify := parts[1:]
//
//	// 2. 验签（先用任意公钥验签，得到 payload）
//	//verifiedPayload, err := jws.Verify([]byte(signedPart), jws.WithKey(jwa.EdDSA, nil))
//	//if err != nil {
//	//	panic(err)
//	//}
//	msg, err := jws.Parse([]byte(signedPart))
//	if err != nil {
//		panic(err)
//	}
//	//var payload string
//	//if msg.MarshalJSON().b64 {
//	//	payload = base64.EncodeToString(msg.payload)
//	//} else {
//	//	payload = string(msg.payload)
//	//}
//	verifiedPayload := msg.Payload()
//	// 3. 从 VC payload 提取公钥 JWK
//	verifiedVCMap := map[string]interface{}{}
//	_ = json.Unmarshal(verifiedPayload, &verifiedVCMap)
//	cnf, ok := verifiedVCMap["cnf"].(map[string]interface{})
//	if !ok {
//		panic("VC 中未找到 cnf 字段")
//	}
//	jwkMap, ok := cnf["jwk"].(map[string]interface{})
//	if !ok {
//		panic("VC 中未找到 cnf.jwk 字段")
//	}
//	jwkBytes, _ := json.Marshal(jwkMap)
//	pubJWKFromVC, err := jwk.ParseKey(jwkBytes)
//	if err != nil {
//		panic("解析 VC 中的公钥 JWK 失败: " + err.Error())
//	}
//	var pubKey ed25519.PublicKey
//	_ = pubJWKFromVC.Raw(&pubKey)
//
//	// 3. 用提取的公钥重新验签
//	_, err = jws.Verify([]byte(signedPart), jws.WithKey(jwa.EdDSA, pubKey))
//	if err != nil {
//		panic("验证失败: " + err.Error())
//	}
//
//	// 4. 还原 VC
//	verifiedVC := verifiedVCMap
//	vcSub := verifiedVC["credentialSubject"].(map[string]interface{})
//	_sd := vcSub["_sd"].([]interface{})
//	for _, encoded := range disclosuresToVerify {
//		raw, _ := base64.RawURLEncoding.DecodeString(encoded)
//		var disclosure []interface{}
//		_ = json.Unmarshal(raw, &disclosure)
//		key := disclosure[1].(string)
//		value := disclosure[2]
//
//		digest := sha256.Sum256([]byte(encoded))
//		digestB64 := base64.RawURLEncoding.EncodeToString(digest[:])
//
//		found := false
//		for _, d := range _sd {
//			if d == digestB64 {
//				found = true
//				break
//			}
//		}
//		if found {
//			vcSub[key] = value
//		}
//	}
//	delete(vcSub, "_sd")
//
//	// 5. 打印验证结果
//	fmt.Println("\n✅ 验证成功，披露后 VC：")
//	out, _ := json.MarshalIndent(verifiedVC, "", "  ")
//	fmt.Println(string(out))
//
//	// 6. 生成 VP
//	vp := map[string]interface{}{
//		"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
//		"type":                 []interface{}{"VerifiablePresentation"},
//		"verifiableCredential": []interface{}{verifiedVC},
//	}
//	fmt.Println("\n📦 生成的 VP (包含披露后的 VC)：")
//	vpOut, _ := json.MarshalIndent(vp, "", "  ")
//	fmt.Println(string(vpOut))
//}
