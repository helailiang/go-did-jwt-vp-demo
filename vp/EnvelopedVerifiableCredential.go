package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"

	go_sd_jwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
)

// 学校学生信息结构体
type SchoolStudentInfo struct {
	StudentID string `json:"student_id"` // 学号
	Name      string `json:"name"`       // 姓名
	Major     string `json:"major"`      // 专业
	Age       int    `json:"age"`        // 年龄
	Grade     string `json:"grade"`      // 成绩
}

// 商店会员信息结构体
type ShopMemberInfo struct {
	MemberID string `json:"member_id"` // 会员号
	Name     string `json:"name"`      // 姓名
	Points   int    `json:"points"`    // 积分
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

// 可验证展示结构体
type VerifiablePresentation struct {
	Context              []string               `json:"@context"`
	ID                   string                 `json:"id"`
	Type                 []string               `json:"type"`
	Holder               string                 `json:"holder"`
	VerifiableCredential []string               `json:"verifiableCredential"`
	IssuanceDate         string                 `json:"issuanceDate"`
	CNF                  map[string]interface{} `json:"cnf,omitempty"`
}

// 新增：信封结构体
// EnvelopedVerifiableCredential for SD-JWT envelope
// https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credential

type EnvelopedVerifiableCredential struct {
	Context interface{} `json:"@context"`
	Type    interface{} `json:"type"`
	ID      string      `json:"id"`
}

type VerifiablePresentationV2 struct {
	Context              []string                        `json:"@context"`
	Type                 string                          `json:"type"`
	VerifiableCredential []EnvelopedVerifiableCredential `json:"verifiableCredential"`
}

func main() {
	fmt.Println("🎓 学校 VC 和 🛒 商店 VC 选择性披露演示")
	fmt.Println(strings.Repeat("=", 60))

	// 1. 构造学校学生信息
	schoolInfo := SchoolStudentInfo{
		StudentID: "2023001",
		Name:      "张三",
		Major:     "计算机科学与技术",
		Age:       20,
		Grade:     "A",
	}

	// 2. 构造商店会员信息
	shopInfo := ShopMemberInfo{
		MemberID: "VIP-888",
		Name:     "张三",
		Points:   1000,
	}

	// =================== 学校颁发 VC ===================
	fmt.Println("\n🏫 学校颁发 VC...")
	schoolVC, err := issueSchoolVC("did:example:student:001", schoolInfo)
	if err != nil {
		panic("学校颁发 VC 失败: " + err.Error())
	}
	fmt.Println("✅ 学校 VC 颁发成功")

	// =================== 商店颁发 VC ===================
	fmt.Println("\n🛒 商店颁发 VC...")
	shopVC, err := issueShopVC("did:example:student:001", shopInfo)
	if err != nil {
		panic("商店颁发 VC 失败: " + err.Error())
	}
	fmt.Println("✅ 商店 VC 颁发成功")

	// =================== 持有者选择性披露 ===================
	fmt.Println("\n👤 持有者进行选择性披露...")

	fmt.Println("学校 VC 选择性披露：只披露学号、专业")
	// 学校 VC 选择性披露：只披露学号、专业
	schoolVP, err := presentSDJWT(schoolVC, []string{"student_id", "major"})
	if err != nil {
		panic("学校 VC 选择性披露失败: " + err.Error())
	}
	fmt.Println("✅ 学校 VC 选择性披露成功")

	// 商店 VC 选择性披露：只披露会员号
	fmt.Println("商店 VC 选择性披露：只披露会员号")
	shopVP, err := presentSDJWT(shopVC, []string{"member_id"})
	if err != nil {
		panic("商店 VC 选择性披露失败: " + err.Error())
	}
	fmt.Println("✅ 商店 VC 选择性披露成功")

	// =================== 创建 VP ===================
	fmt.Println("\n📋 创建 Verifiable Presentation...")
	vp, err := createVP("did:example:student:001", []string{schoolVP, shopVP})
	if err != nil {
		panic("创建 VP 失败: " + err.Error())
	}
	fmt.Println("✅ VP 创建成功")

	// =================== 验证 VP ===================
	fmt.Println("\n🔍 验证 Verifiable Presentation...")
	err = verifyVP(vp)
	if err != nil {
		fmt.Println("❌ VP 验证失败:", err)
	} else {
		fmt.Println("✅ VP 验证成功")
	}

	// =================== 创建 v2 VP（信封格式） ===================
	fmt.Println("\n📋 创建 W3C v2 Enveloped Verifiable Presentation...")
	vpV2 := VerifiablePresentationV2{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		Type: "VerifiablePresentation",
		VerifiableCredential: []EnvelopedVerifiableCredential{
			{
				Context: "https://www.w3.org/ns/credentials/v2",
				Type:    "EnvelopedVerifiableCredential",
				ID:      "data:application/vc+sd-jwt," + schoolVP,
			},
			{
				Context: "https://www.w3.org/ns/credentials/v2",
				Type:    "EnvelopedVerifiableCredential",
				ID:      "data:application/vc+sd-jwt," + shopVP,
			},
		},
	}
	vpV2Json, _ := json.MarshalIndent(vpV2, "", "  ")
	fmt.Println("\n================ W3C v2 VP (EnvelopedVerifiableCredential) ================")
	fmt.Println(string(vpV2Json))
	fmt.Println("======================================================\n")

	// =================== 输出单个 VC 的 W3C v2 信封格式 ===================
	fmt.Println("\n================ W3C v2 VC (Enveloped, 学校) ================")
	envelopedSchoolVC := EnvelopedVerifiableCredential{
		Context: "https://www.w3.org/ns/credentials/v2",
		Type:    "EnvelopedVerifiableCredential",
		ID:      "data:application/vc+sd-jwt," + schoolVP,
	}
	vcSchoolJson, _ := json.MarshalIndent(envelopedSchoolVC, "", "  ")
	fmt.Println(string(vcSchoolJson))
	fmt.Println("==========================================================\n")

	fmt.Println("\n================ W3C v2 VC (Enveloped, 商店) ================")
	envelopedShopVC := EnvelopedVerifiableCredential{
		Context: "https://www.w3.org/ns/credentials/v2",
		Type:    "EnvelopedVerifiableCredential",
		ID:      "data:application/vc+sd-jwt," + shopVP,
	}
	vcShopJson, _ := json.MarshalIndent(envelopedShopVC, "", "  ")
	fmt.Println(string(vcShopJson))
	fmt.Println("==========================================================\n")

	// =================== 显示最终结果 ===================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🎯 最终结果:")
	fmt.Println("📚 学校 VC 披露字段: 学号、专业")
	fmt.Println("🛒 商店 VC 披露字段: 会员号")
	fmt.Println("🔒 隐藏字段: 姓名、年龄、成绩、积分")
	fmt.Println(strings.Repeat("=", 60))

	// 显示具体的披露内容
	fmt.Println("\n📋 选择性披露详情:")
	fmt.Println("🏫 学校 VC 披露内容:")
	fmt.Printf("   - 学号: %s\n", schoolInfo.StudentID)
	fmt.Printf("   - 专业: %s\n", schoolInfo.Major)
	fmt.Println("   - 隐藏: 姓名、年龄、成绩")

	fmt.Println("\n🛒 商店 VC 披露内容:")
	fmt.Printf("   - 会员号: %s\n", shopInfo.MemberID)
	fmt.Println("   - 隐藏: 姓名、积分")

	fmt.Println("\n✅ 选择性披露演示完成！")
	fmt.Println("💡 验证者只能看到学号、专业、会员号，无法看到姓名、年龄、成绩、积分等敏感信息")
}

// 学校颁发 VC
func issueSchoolVC(subject string, schoolInfo SchoolStudentInfo) (string, error) {
	// 1. 生成 P-256 (ES256) 密钥对
	issuerSigner, err := jws.GetSigner(model.ES256, &model.Opts{BitSize: 256})
	if err != nil {
		return "", fmt.Errorf("创建学校签名器失败: %w", err)
	}

	// 2. 生成 nonce
	nonceBytes := make([]byte, 16)
	_, err = rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("生成 nonce 失败: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	// 3. 构造学校 VC payload
	vc := VerifiableCredential{
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "https://school.example.edu/credentials/2023001",
		Type:         []string{"VerifiableCredential", "SchoolCredential"},
		Issuer:       "did:example:school",
		IssuanceDate: time.Now().Format(time.RFC3339),
		CredentialSubject: map[string]interface{}{
			"id": subject,
		},
		Nonce: nonce,
	}

	// 4. 将学校信息转换为 map
	schoolMap := map[string]interface{}{
		"student_id": schoolInfo.StudentID,
		"name":       schoolInfo.Name,
		"major":      schoolInfo.Major,
		"age":        schoolInfo.Age,
		"grade":      schoolInfo.Grade,
	}

	// 5. 创建 disclosures 和 digests
	var disclosures []disclosure.Disclosure
	var sdDigests []string

	for key, value := range schoolMap {
		saltBytes := make([]byte, 16)
		_, err := rand.Read(saltBytes)
		if err != nil {
			return "", fmt.Errorf("生成 salt 失败: %w", err)
		}
		salt := base64.RawURLEncoding.EncodeToString(saltBytes)
		dis, err := disclosure.NewFromObject(key, value, &salt)
		if err != nil {
			return "", fmt.Errorf("创建 disclosure 失败: %w", err)
		}
		disclosures = append(disclosures, *dis)
		hash := dis.Hash(sha256.New())
		sdDigests = append(sdDigests, base64.RawURLEncoding.EncodeToString(hash))
	}

	// 6. 将 digests 添加到 VC
	vc.SD = sdDigests
	vc.Alg = "sha-256"

	// 7. 创建 JWK 并嵌入 VC
	cnf, err := jwk.PublicJwk(issuerSigner.Public())
	if err != nil {
		return "", fmt.Errorf("创建 JWK 失败: %w", err)
	}
	vc.CNF = map[string]interface{}{"jwk": *cnf}

	// 8. 组装 JWT
	header := map[string]string{
		"typ": "application/json+sd-jwt",
		"alg": issuerSigner.Alg().String(),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("序列化 header 失败: %w", err)
	}
	b64Header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBytes, _ := json.Marshal(vc)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := b64Header + "." + payloadB64

	sig, err := issuerSigner.Sign(rand.Reader, []byte(signingInput), nil)
	if err != nil {
		return "", fmt.Errorf("签名失败: %w", err)
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(sig)
	jwtString := b64Header + "." + payloadB64 + "." + signatureB64

	// 9. 构造 SD-JWT token
	disclosureStrings := make([]string, len(disclosures))
	for i, d := range disclosures {
		disclosureStrings[i] = d.EncodedValue
	}

	token := jwtString
	if len(disclosures) > 0 {
		token = fmt.Sprintf("%s~%s~", token, strings.Join(disclosureStrings, "~"))
	}

	return token, nil
}

// 商店颁发 VC
func issueShopVC(subject string, shopInfo ShopMemberInfo) (string, error) {
	// 1. 生成 P-256 (ES256) 密钥对
	issuerSigner, err := jws.GetSigner(model.ES256, &model.Opts{BitSize: 256})
	if err != nil {
		return "", fmt.Errorf("创建商店签名器失败: %w", err)
	}

	// 2. 生成 nonce
	nonceBytes := make([]byte, 16)
	_, err = rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("生成 nonce 失败: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	// 3. 构造商店 VC payload
	vc := VerifiableCredential{
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "https://shop.example.com/credentials/VIP-888",
		Type:         []string{"VerifiableCredential", "ShopCredential"},
		Issuer:       "did:example:shop",
		IssuanceDate: time.Now().Format(time.RFC3339),
		CredentialSubject: map[string]interface{}{
			"id": subject,
		},
		Nonce: nonce,
	}

	// 4. 将商店信息转换为 map
	shopMap := map[string]interface{}{
		"member_id": shopInfo.MemberID,
		"name":      shopInfo.Name,
		"points":    shopInfo.Points,
	}

	// 5. 创建 disclosures 和 digests
	var disclosures []disclosure.Disclosure
	var sdDigests []string

	for key, value := range shopMap {
		saltBytes := make([]byte, 16)
		_, err := rand.Read(saltBytes)
		if err != nil {
			return "", fmt.Errorf("生成 salt 失败: %w", err)
		}
		salt := base64.RawURLEncoding.EncodeToString(saltBytes)
		dis, err := disclosure.NewFromObject(key, value, &salt)
		if err != nil {
			return "", fmt.Errorf("创建 disclosure 失败: %w", err)
		}
		disclosures = append(disclosures, *dis)
		hash := dis.Hash(sha256.New())
		sdDigests = append(sdDigests, base64.RawURLEncoding.EncodeToString(hash))
	}

	// 6. 将 digests 添加到 VC
	vc.SD = sdDigests
	vc.Alg = "sha-256"

	// 7. 创建 JWK 并嵌入 VC
	cnf, err := jwk.PublicJwk(issuerSigner.Public())
	if err != nil {
		return "", fmt.Errorf("创建 JWK 失败: %w", err)
	}
	vc.CNF = map[string]interface{}{"jwk": *cnf}

	// 8. 组装 JWT
	header := map[string]string{
		"typ": "application/json+sd-jwt",
		"alg": issuerSigner.Alg().String(),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("序列化 header 失败: %w", err)
	}
	b64Header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBytes, _ := json.Marshal(vc)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := b64Header + "." + payloadB64

	sig, err := issuerSigner.Sign(rand.Reader, []byte(signingInput), nil)
	if err != nil {
		return "", fmt.Errorf("签名失败: %w", err)
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(sig)
	jwtString := b64Header + "." + payloadB64 + "." + signatureB64

	// 9. 构造 SD-JWT token
	disclosureStrings := make([]string, len(disclosures))
	for i, d := range disclosures {
		disclosureStrings[i] = d.EncodedValue
	}

	token := jwtString
	if len(disclosures) > 0 {
		token = fmt.Sprintf("%s~%s~", token, strings.Join(disclosureStrings, "~"))
	}

	return token, nil
}

// 创建 Verifiable Presentation
func createVP(holder string, vcs []string) (string, error) {
	// 1. 生成持有者密钥对
	holderSigner, err := jws.GetSigner(model.ES256, &model.Opts{BitSize: 256})
	if err != nil {
		return "", fmt.Errorf("创建持有者签名器失败: %w", err)
	}

	// 2. 构造 VP
	vp := VerifiablePresentation{
		Context:              []string{"https://www.w3.org/2018/credentials/v1"},
		ID:                   "https://example.com/presentations/001",
		Type:                 []string{"VerifiablePresentation"},
		Holder:               holder,
		VerifiableCredential: vcs,
		IssuanceDate:         time.Now().Format(time.RFC3339),
	}

	// 3. 创建 JWK 并嵌入 VP
	cnf, err := jwk.PublicJwk(holderSigner.Public())
	if err != nil {
		return "", fmt.Errorf("创建 JWK 失败: %w", err)
	}
	vp.CNF = map[string]interface{}{"jwk": *cnf}

	// 4. 签名 VP
	header := map[string]string{
		"typ": "application/json+sd-jwt",
		"alg": holderSigner.Alg().String(),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("序列化 header 失败: %w", err)
	}
	b64Header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBytes, _ := json.Marshal(vp)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := b64Header + "." + payloadB64

	sig, err := holderSigner.Sign(rand.Reader, []byte(signingInput), nil)
	if err != nil {
		return "", fmt.Errorf("签名失败: %w", err)
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(sig)

	// 5. 构造 JWT
	jwtString := b64Header + "." + payloadB64 + "." + signatureB64

	return jwtString, nil
}

// 验证 Verifiable Presentation
func verifyVP(vpToken string) error {
	// 1. 解析 JWT
	parts := strings.Split(vpToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("VP JWT 格式错误")
	}

	headerB64 := parts[0]
	payloadB64 := parts[1]
	signatureB64 := parts[2]

	// 2. 解析 payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return fmt.Errorf("payload base64 解码失败: %w", err)
	}

	var vp VerifiablePresentation
	if err := json.Unmarshal(payloadBytes, &vp); err != nil {
		return fmt.Errorf("payload 反序列化失败: %w", err)
	}

	// 3. 验证 VP 签名
	cnf := vp.CNF
	if cnf == nil {
		return fmt.Errorf("VP 中缺少 cnf 字段")
	}
	jwkMap, ok := cnf["jwk"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("VP 中缺少 cnf.jwk 字段")
	}
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return fmt.Errorf("序列化 JWK 失败: %w", err)
	}

	pubJwk, err := jws.GetValidatorFromJwk(model.ES256, jwkBytes)
	if err != nil {
		return fmt.Errorf("JWK 解析失败: %w", err)
	}

	signingInput := headerB64 + "." + payloadB64
	sig, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("签名 base64 解码失败: %w", err)
	}

	valid, err := pubJwk.ValidateSignature([]byte(signingInput), sig)
	if err != nil {
		return fmt.Errorf("VP 签名验证失败: %w", err)
	}
	if !valid {
		return fmt.Errorf("VP 签名验证失败")
	}

	// 4. 验证每个 VC
	for i, vcToken := range vp.VerifiableCredential {
		fmt.Printf("验证 VC %d...\n", i+1)
		if err := verifySDJWT(vcToken); err != nil {
			return fmt.Errorf("VC %d 验证失败: %w", i+1, err)
		}
	}

	return nil
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
