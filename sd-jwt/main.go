package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"

	go_sd_jwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
)

// 用户信息结构体，参考 go-sd-jwt e2e 测试
type UserInfo struct {
	Name    string `json:"name"`
	Age     int    `json:"age"`
	Email   string `json:"email"`
	Address string `json:"address"`
}

// 可验证凭证结构体
type VerifiableCredential struct {
	Context           []string               `json:"@context"`
	ID                string                 `json:"id"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	IssuanceDate      string                 `json:"issuanceDate"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	SD                []string               `json:"_sd,omitempty"`
	CNF               map[string]interface{} `json:"cnf,omitempty"`
	Nonce             string                 `json:"nonce,omitempty"`
	Alg               string                 `json:"_sd_alg,omitempty"`
}

func main() {
	// 1. 构造用户信息 (原始完整数据)
	userInfo := UserInfo{
		Name:    "Alice",
		Age:     30,
		Email:   "alice@example.com",
		Address: "北京望京",
	}

	// =================== Issuer 流程: 使用 go-sd-jwt 生成 SD-JWT ===================
	fmt.Println("🔐 Issuer 开始使用 go-sd-jwt 生成 SD-JWT...")
	sdJwtToken, err := issueSDJWT("did:example:holder", userInfo)
	if err != nil {
		panic("发行 SD-JWT 失败: " + err.Error())
	}
	fmt.Println("✅ Issuer 使用 go-sd-jwt 生成的 SD-JWT:")
	fmt.Println(sdJwtToken)

	// =================== Holder 流程: 使用 go-sd-jwt 进行选择性披露 ===================
	fmt.Println("\n🔐 Holder 开始使用 go-sd-jwt 进行选择性披露...")
	// Holder 决定只披露 name 和 address
	keysToPresent := []string{"name", "address"}
	holderSDJwt, err := presentSDJWT(sdJwtToken, keysToPresent)
	if err != nil {
		panic("Holder 选择性披露失败: " + err.Error())
	}
	fmt.Println("✅ Holder 使用 go-sd-jwt 选择性披露后的 SD-JWT:")
	fmt.Println(holderSDJwt)

	// =================== Verifier 流程: 使用 go-sd-jwt 验证 SD-JWT ===================
	fmt.Println("\n🔍 Verifier 开始使用 go-sd-jwt 验证 SD-JWT...")
	err = verifySDJWT(holderSDJwt)
	if err != nil {
		fmt.Println("❌ 验证失败:", err)
	} else {
		fmt.Println("✅ 验证成功")
	}
}

// Issuer 使用 go-sd-jwt 发行 SD-JWT
func issueSDJWT(subject string, userInfo UserInfo) (string, error) {
	// 1. 生成 P-256 (ES256) 密钥对（go-jose）
	issuerSigner, err := jws.GetSigner(model.ES256, &model.Opts{BitSize: 256})
	if err != nil {
		panic(fmt.Sprintf("error creating issuer signer: %s", err.Error()))
	}
	issuerValidator, err := jws.GetValidator(issuerSigner.Alg(), issuerSigner.Public())
	if err != nil {
		panic(fmt.Sprintf("error creating issuer validator: %s", err.Error()))
	}

	// 1.1 生成 nonce
	nonceBytes := make([]byte, 16)
	_, err = rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("生成 nonce 失败: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	// 2. 构造 VC payload
	vc := VerifiableCredential{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		ID:      "https://example.edu/credentials/1872",
		Type:    []string{"VerifiableCredential"},
		Issuer:  "did:example:issuer",
		CredentialSubject: map[string]interface{}{
			"id": subject,
		},
		Nonce: nonce,
	}

	// 3. 将用户信息转换为 map 以便处理
	userMap := map[string]interface{}{
		"name":    userInfo.Name,
		"age":     userInfo.Age,
		"email":   userInfo.Email,
		"address": userInfo.Address,
	}

	// 4. 创建 disclosures 和 digests
	var disclosures []disclosure.Disclosure
	var sdDigests []string

	for key, value := range userMap {
		saltBytes := make([]byte, 16)
		_, err := rand.Read(saltBytes)
		if err != nil {
			return "", fmt.Errorf("生成 salt 失败: %w", err)
		}
		salt := base64.RawURLEncoding.EncodeToString(saltBytes)
		dis, err := disclosure.NewFromObject(key, value, &salt)
		if err != nil {
			return "", fmt.Errorf("使用 go-sd-jwt 创建 disclosure 失败: %w", err)
		}
		disclosures = append(disclosures, *dis)
		hash := dis.Hash(sha256.New())
		sdDigests = append(sdDigests, base64.RawURLEncoding.EncodeToString(hash))
	}

	// 5. 将 digests 添加到 VC (SD-JWT 规范要求)
	vc.SD = sdDigests
	vc.Alg = "sha-256"
	// 6. 创建 JWK 并嵌入 VC (用于验证)
	cnf, err := jwk.PublicJwk(issuerSigner.Public())
	if err != nil {
		panic(err)
	}
	vc.CNF = map[string]interface{}{"jwk": *cnf}

	// 7. 组装 JWT（JWS）
	header := map[string]string{
		"typ": "application/json+sd-jwt",
		"alg": issuerSigner.Alg().String(),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		panic(fmt.Sprintf("error marshalling header as bytes: %s", err.Error()))
	}
	b64Header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBytes, _ := json.Marshal(vc)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := b64Header + "." + payloadB64

	sig, err := issuerSigner.Sign(rand.Reader, []byte(signingInput), nil)
	if err != nil {
		panic(fmt.Errorf("签名失败: %w", err))
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(sig)
	jwtString := string(b64Header) + "." + payloadB64 + "." + signatureB64

	// 8. 使用 go-sd-jwt.NewFromComponents 构造 SD-JWT token
	disclosureStrings := make([]string, len(disclosures))
	for i, d := range disclosures {
		disclosureStrings[i] = d.EncodedValue
	}
	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("JWT 格式错误")
	}
	//sdJwt, err := go_sd_jwt.NewFromComponents(
	//	parts[0], parts[1], parts[2], disclosureStrings, nil,
	//)
	token := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	if len(disclosures) > 0 {
		token = fmt.Sprintf("%s~%s~", token, strings.Join(disclosureStrings, "~"))
	}
	//if kbJwt != nil {
	//	token = fmt.Sprintf("%s%s", token, *kbJwt)
	//}
	if err != nil {
		return "", fmt.Errorf("使用 go-sd-jwt 创建 SD-JWT 失败: %w", err)
	}

	//tokenPtr, err := sdJwt.Token()
	//if err != nil {
	//	return "", fmt.Errorf("使用 go-sd-jwt 获取 SD-JWT token 失败: %w", err)
	//}
	aa, _ := jwk.PublicJwk(issuerValidator.Public())
	fmt.Println("aaaa=====>", aa)
	fmt.Println("aaaa=====>", payloadB64)
	fmt.Println("aaaa=====>", sha256.Sum256([]byte(signingInput)))
	fmt.Println("aaaa=====>", sha256.Sum256([]byte(sig)))
	valid, err := issuerValidator.ValidateSignature([]byte(signingInput), sig)
	if err != nil {
		panic(err)
	}
	if !valid {
		panic(fmt.Errorf("JWT 签名验证失败"))

	}
	return token, nil
}

// Holder 使用 go-sd-jwt 进行选择性披露
func presentSDJWT(sdJwtToken string, revealFields []string) (string, error) {
	// 1. 拆分 SD-JWT
	parts := strings.Split(sdJwtToken, "~")
	if len(parts) < 1 {
		return "", fmt.Errorf("SD-JWT 格式错误")
	}
	jwt := parts[0]
	allDisclosures := parts[1:]

	// 2. 只保留需要披露的 disclosures
	var selectedDisclosures []string
	for _, d := range allDisclosures {
		// disclosure 是 base64url 编码的 JSON 数组 [salt, key, value]
		decoded, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			continue
		}
		var arr []interface{}
		if err := json.Unmarshal(decoded, &arr); err != nil || len(arr) < 3 {
			continue
		}
		key, ok := arr[1].(string)
		if !ok {
			continue
		}
		if contains(revealFields, key) {
			selectedDisclosures = append(selectedDisclosures, d)
		}
	}

	// 3. 组装新的 SD-JWT
	result := jwt
	if len(selectedDisclosures) > 0 {
		result += "~" + strings.Join(selectedDisclosures, "~")
	}
	// 保证以 ~ 结尾
	if !strings.HasSuffix(result, "~") {
		result += "~"
	}
	return result, nil
}

// Verifier 使用 go-sd-jwt 验证 SD-JWT
func verifySDJWT(sdJwtToken string) error {
	fmt.Println("verifySDJWT sdJwtToken============>", sdJwtToken)
	// 1. 使用 go-sd-jwt.New 解析 SD-JWT
	sdJwt, err := go_sd_jwt.New(sdJwtToken)
	if err != nil {
		return fmt.Errorf("使用 go-sd-jwt 解析 SD-JWT 失败: %w", err)
	}
	// 1.1 验证 JWT 签名（go-jose）
	parts := strings.Split(sdJwtToken, "~")
	if len(parts) < 1 {
		return fmt.Errorf("SD-JWT 格式错误")
	}
	jwtParts := strings.Split(parts[0], ".")
	if len(jwtParts) != 3 {
		return fmt.Errorf("JWT 格式错误")
	}
	headerB64 := jwtParts[0]
	payloadB64 := jwtParts[1]

	signatureB64 := jwtParts[2]

	vcPayload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return fmt.Errorf("payload base64 解码失败: %w", err)
	}
	var vcMap map[string]interface{}
	if err := json.Unmarshal(vcPayload, &vcMap); err != nil {
		return fmt.Errorf("payload 反序列化失败: %w", err)
	}
	cnf, ok := vcMap["cnf"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("VC 中缺少 cnf 字段")
	}
	jwkMap, ok := cnf["jwk"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("VC 中缺少 cnf.jwk 字段")
	}
	jwkBytes, err := json.Marshal(jwkMap)
	pubJwk, err := jws.GetValidatorFromJwk(model.ES256, jwkBytes)
	if err != nil {
		return fmt.Errorf("JWK 解析失败: %w", err)
	}

	signingInput := headerB64 + "." + payloadB64
	sig, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("签名 base64 解码失败: %w", err)
	}
	aa, _ := jwk.PublicJwk(pubJwk.Public())
	fmt.Println("bbbb=====>", aa)

	valid, err := pubJwk.ValidateSignature([]byte(signingInput), sig)
	if err != nil {
		panic(err)
	}
	if !valid {
		fmt.Println(fmt.Errorf("JWT 签名验证失败"))
		return fmt.Errorf("JWT 签名验证失败")
	}
	fmt.Println("\n✅ JWT 签名验证通过")

	// 2. 手动验证 disclosures 和 _sd 数组的匹配
	sdArray, ok := sdJwt.Body["_sd"].([]interface{})
	if !ok {
		return fmt.Errorf("VC 中缺少 _sd 数组")
	}

	// 将 _sd 数组转换为字符串切片
	sdDigests := make([]string, len(sdArray))
	for i, v := range sdArray {
		if digest, ok := v.(string); ok {
			sdDigests[i] = digest
		} else {
			return fmt.Errorf("_sd 数组中的元素不是字符串")
		}
	}
	//fmt.Println("获取Claims")
	//data, err := sdJwt.GetDisclosedClaims()
	//if err != nil {
	//	panic(err)
	//}
	//for s, a := range data {
	//	fmt.Printf("%s :  %s \n", s, a)
	//}
	// 验证每个 disclosure 的 digest 都在 _sd 数组中
	disclosedClaims := make(map[string]interface{})
	for _, d := range sdJwt.Disclosures {
		hash := d.Hash(sha256.New())
		digest := base64.RawURLEncoding.EncodeToString(hash)

		// 检查 digest 是否在 _sd 数组中
		found := false
		for _, sdDigest := range sdDigests {
			if digest == sdDigest {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("disclosure 的 digest %s 不在 _sd 数组中", digest)
		}

		// 将披露的 claim 添加到结果中
		if d.Key != nil {
			disclosedClaims[*d.Key] = d.Value
		}
	}

	// 3. 打印验证结果
	fmt.Println("\n✅ 使用 go-sd-jwt 验证成功，披露的 claims:")
	prettyPrint(disclosedClaims)

	return nil
}

// 辅助函数
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func prettyPrint(v interface{}) {
	bytes, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(bytes))
}
