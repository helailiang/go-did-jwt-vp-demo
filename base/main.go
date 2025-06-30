package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// 声明的键值对
type ClaimKV struct {
	Name  string
	Value string
}

// 生成 Disclosure（盐 + 键 + 值 → base64url）
func createDisclosure(key string, value interface{}) (string, string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", "", err
	}
	disclosure := []interface{}{base64.RawURLEncoding.EncodeToString(salt), key, value}
	jsonBytes, err := json.Marshal(disclosure)
	if err != nil {
		return "", "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(jsonBytes)
	// 计算 disclosure 的 digest（sha256）
	digest := sha256.Sum256([]byte(encoded))
	digestB64 := base64.RawURLEncoding.EncodeToString(digest[:])
	return encoded, digestB64, nil
}

func main() {
	// 1. 构造 VC claims (原始完整数据)
	claims := []ClaimKV{
		{"name", "Alice"},
		{"age", "30"},
		{"email", "alice@example.com"},
		{"address", "北京望京"},
	}

	// =================== Issuer 流程: 生成所有 Disclosures ===================
	// 3. 定义所有可披露字段，并生成其 Disclosures 和 Digests
	signedJWT, disclosures, err := issueSDJWT("did:example:holder", claims)
	if err != nil {
		panic(err)
	}
	PrintJWTVP(string(signedJWT))

	fmt.Println(" issued SD-JWT VC ========》")
	sdjwt, err := presentVC(string(signedJWT), disclosures)
	if err != nil {
		panic(err)
	}
	fmt.Println(" issued SD-JWT VC 内容为：", sdjwt)
	PrintJWTVP(string(sdjwt))

	// =================== Holder 流程: 选择性披露 ===================
	//  Holder 决定只披露 name 和 address
	fmt.Println("\n issued  SD-JWT+KB  VP ========》")

	keysToPresent := []string{"name", "address"}
	sdjwtKB, err := presentVP(sdjwt, keysToPresent)
	if err != nil {
		panic(err)
	}
	fmt.Println("🔐 SD-JWT--KB VP披露 ========》:")
	fmt.Println(sdjwtKB)
	// ======== Verifier 流程 ========
	fmt.Println("\n🔍 开始验证 SD-JWT-KB ========》")
	err = verifyVP(sdjwtKB)
	if err != nil {
		fmt.Println("❌ 验证失败:", err)
	} else {
		fmt.Println("✅ 验证成功")
	}

}

func issueSDJWT(subject string, claims []ClaimKV) ([]byte, map[string]string, error) {
	disclosures := make(map[string]string)
	disclosureDigests := make([]string, 0)

	for _, c := range claims {
		//加盐值
		salt := make([]byte, 16)
		_, err := rand.Read(salt)
		if err != nil {
			return nil, nil, err
		}
		dBytes, _ := json.Marshal([]interface{}{base64.RawURLEncoding.EncodeToString(salt), c.Name, c.Value})
		encoded := base64.RawURLEncoding.EncodeToString(dBytes)

		hash := sha256.Sum256([]byte(encoded))
		hashB64 := base64.RawURLEncoding.EncodeToString(hash[:])

		disclosures[hashB64] = encoded
		disclosureDigests = append(disclosureDigests, hashB64)
	}
	vcPayloadSubject := make(map[string]interface{})
	vcPayloadSubject["_sd"] = disclosureDigests

	// 2. 生成 Ed25519 JWK
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	jwkKey, _ := jwk.Import(privKey)
	jwkKey.Set(jwk.KeyIDKey, "issuer-key")
	jwkKey.Set(jwk.AlgorithmKey, jwa.EdDSA)
	// 4. 构造用于签名的 VC
	vcForSigning := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/2018/credentials/v1",
		},
		"id":                "https://example.edu/credentials/1872",
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"issuanceDate":      time.Now().Format(time.RFC3339),
		"credentialSubject": vcPayloadSubject,
	}

	// 4.1 将公钥嵌入 VC
	pubJWK, _ := jwkKey.PublicKey()
	pubJWKBytes, err := json.Marshal(pubJWK)
	if err != nil {
		panic("Marshal 公钥失败: " + err.Error())
	}
	var pubJWKMap map[string]interface{}
	if err := json.Unmarshal(pubJWKBytes, &pubJWKMap); err != nil {
		panic("Unmarshal 公钥失败: " + err.Error())
	}
	vcForSigning["cnf"] = map[string]interface{}{"jwk": pubJWKMap}
	payload, _ := json.Marshal(vcForSigning)

	// 5. 签名
	var signer ed25519.PrivateKey
	// _ = jwkKey.Raw(&signer)
	signedJWT, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), signer))
	if err != nil {
		panic(err)
	}

	return signedJWT, disclosures, nil
}

func presentVC(sdJWT string, disclosures map[string]string) (string, error) {
	parts := strings.Split(sdJWT, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid SD-JWT format")
	}

	// 只选择需要披露的字段
	selectedDisclosures := make([]string, 0)
	for _, disclosure := range disclosures {
		data, _ := base64.RawURLEncoding.DecodeString(disclosure)
		var arr []string
		_ = json.Unmarshal(data, &arr)
		selectedDisclosures = append(selectedDisclosures, disclosure)
	}

	// 7. Holder 组合最终的 SD-JWT
	sdjwt := sdJWT + "~" + strings.Join(selectedDisclosures, "~")

	return sdjwt, nil
}

// ------------------- Holder 构建 VP -------------------

func presentVP(sdJWT string, revealFields []string) (string, error) {
	parts := strings.Split(sdJWT, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid SD-JWT format")
	}
	allDisclosuresParts := strings.Split(sdJWT, "~")
	allDisclosures := allDisclosuresParts[1:]
	disclosures := make(map[string]string)

	for _, encoded := range allDisclosures {
		//raw, err := base64.RawURLEncoding.DecodeString(encoded)
		//if err != nil {
		//	panic(err)
		//}
		//var disclosure []interface{}
		//_ = json.Unmarshal(raw, &disclosure)
		//salt := disclosure[0].(string)
		//key := disclosure[1].(string)
		//value := disclosure[2]

		digest := sha256.Sum256([]byte(encoded))
		digestB64 := base64.RawURLEncoding.EncodeToString(digest[:])
		disclosures[digestB64] = encoded

	}

	// 只选择需要披露的字段
	selectedDisclosures := make([]string, 0)
	for _, disclosure := range disclosures {
		data, _ := base64.RawURLEncoding.DecodeString(disclosure)
		var arr []string
		_ = json.Unmarshal(data, &arr)
		if contains(revealFields, arr[1]) {
			selectedDisclosures = append(selectedDisclosures, disclosure)
		}
	}

	// 7. Holder 组合最终的 SD-JWT
	sdjwt := allDisclosuresParts[0] + "~" + strings.Join(selectedDisclosures, "~")

	return sdjwt, nil
}

func verifyVP(sdjwt string) error {
	parts := strings.Split(sdjwt, "~")
	signedPart := parts[0]
	disclosuresToVerify := parts[1:]

	msg, err := jws.Parse([]byte(signedPart))
	if err != nil {
		panic(err)
	}
	verifiedPayload := msg.Payload()
	// 3. 从 VC payload 提取公钥 JWK
	verifiedVCMap := map[string]interface{}{}
	_ = json.Unmarshal(verifiedPayload, &verifiedVCMap)
	cnf, ok := verifiedVCMap["cnf"].(map[string]interface{})
	if !ok {
		panic("VC 中未找到 cnf 字段")
	}
	jwkMap, ok := cnf["jwk"].(map[string]interface{})
	if !ok {
		panic("VC 中未找到 cnf.jwk 字段")
	}
	jwkBytes, _ := json.Marshal(jwkMap)
	pubJWKFromVC, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		panic("解析 VC 中的公钥 JWK 失败: " + err.Error())
	}
	var pubKey ed25519.PublicKey
	if err := pubJWKFromVC.Get("x", &pubKey); err != nil {
		panic("Get 公钥失败: " + err.Error())
	}

	// 3. 用提取的公钥重新验签
	_, err = jws.Verify([]byte(signedPart), jws.WithKey(jwa.EdDSA(), pubKey))
	if err != nil {
		panic("验证失败: " + err.Error())
	}

	fmt.Println("\n✅ 验签成功")

	// 4. 还原 VC
	verifiedVC := verifiedVCMap
	vcSub := verifiedVC["credentialSubject"].(map[string]interface{})
	_sd := vcSub["_sd"].([]interface{})
	for _, encoded := range disclosuresToVerify {
		raw, _ := base64.RawURLEncoding.DecodeString(encoded)
		var disclosure []interface{}
		_ = json.Unmarshal(raw, &disclosure)
		key := disclosure[1].(string)
		value := disclosure[2]

		digest := sha256.Sum256([]byte(encoded))
		digestB64 := base64.RawURLEncoding.EncodeToString(digest[:])

		found := false
		for _, d := range _sd {
			if d == digestB64 {
				found = true
				break
			}
		}
		if found {
			vcSub[key] = value
		}
	}
	delete(vcSub, "_sd")

	// 5. 打印验证结果
	fmt.Println("\n✅ 验证成功，披露后 VC：")
	out, _ := json.MarshalIndent(verifiedVC, "", "  ")
	fmt.Println(string(out))
	return nil
}

func PrintJWTVP(sdjwt string) {
	parts := strings.Split(sdjwt, "~")
	signedPart := parts[0]
	disclosuresToVerify := parts[1:]

	msg, err := jws.Parse([]byte(signedPart))
	if err != nil {
		panic(err)
	}
	verifiedPayload := msg.Payload()
	// 3. 从 VC payload 提取公钥 JWK
	verifiedVCMap := map[string]interface{}{}
	_ = json.Unmarshal(verifiedPayload, &verifiedVCMap)

	// 5. 打印验证结果
	fmt.Println("\n✅ SD-JWT 有效载荷为：", string(verifiedPayload))

	// 4. 还原 VC
	verifiedVC := verifiedVCMap
	vcSub := verifiedVC["credentialSubject"].(map[string]interface{})
	_sd := vcSub["_sd"].([]interface{})
	for _, encoded := range disclosuresToVerify {
		raw, _ := base64.RawURLEncoding.DecodeString(encoded)
		var disclosure []interface{}
		_ = json.Unmarshal(raw, &disclosure)
		key := disclosure[1].(string)
		value := disclosure[2]

		digest := sha256.Sum256([]byte(encoded))
		digestB64 := base64.RawURLEncoding.EncodeToString(digest[:])

		found := false
		for _, d := range _sd {
			if d == digestB64 {
				found = true
				break
			}
		}
		if found {
			vcSub[key] = value
		}
	}
	delete(vcSub, "_sd")

	// 5. 打印验证结果
	fmt.Println("\n✅ 对SD-JWT 有效负载解码处理后：")
	out, _ := json.MarshalIndent(verifiedVC, "", "  ")
	fmt.Println(string(out))
}
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
