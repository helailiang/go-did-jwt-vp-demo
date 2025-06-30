package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type VerifiableCredential struct {
	Context           string                 `json:"@context"`
	ID                string                 `json:"id"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	IssuanceDate      string                 `json:"issuanceDate"`
	ExpirationDate    string                 `json:"expirationDate"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof             Proof                  `json:"proof"`
}

type VerifiablePresentation struct {
	Context              string                   `json:"@context"`
	ID                   string                   `json:"id"`
	Type                 []string                 `json:"type"`
	Holder               string                   `json:"holder"`
	VerifiableCredential []VerifiableCredential   `json:"verifiableCredential"`
	Proof                Proof                    `json:"proof"`
	ClaimSubject         []map[string]interface{} `json:"claimSubject,omitempty"`
}

type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
	Cryptosuite        string `json:"cryptosuite,omitempty"`
	ProofPurpose       string `json:"proofPurpose,omitempty"`
	ProofValue         string `json:"proofValue,omitempty"`
	Creator            string `json:"creator,omitempty"`
	SignatureValue     string `json:"signatureValue,omitempty"`
}

type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

type MerkleTree struct {
	RootNode *MerkleNode
}

func NewMerkleTree(data [][]byte) *MerkleTree {
	var nodes []MerkleNode
	for _, datum := range data {
		nodes = append(nodes, MerkleNode{nil, nil, datum})
	}

	for len(nodes) > 1 {
		var level []MerkleNode
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}
		for i := 0; i < len(nodes); i += 2 {
			hash := sha256.New()
			hash.Write(nodes[i].Data)
			hash.Write(nodes[i+1].Data)
			parent := MerkleNode{
				Left:  &nodes[i],
				Right: &nodes[i+1],
				Data:  hash.Sum(nil),
			}
			level = append(level, parent)
		}
		nodes = level
	}
	return &MerkleTree{&nodes[0]}
}

func generateSeed() string {
	seed := make([]byte, 16)
	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(seed)
}

func addSalt(data string, seed string, index int) []byte {
	salted := data + seed + strconv.Itoa(index)
	hash := sha256.Sum256([]byte(salted))
	return hash[:]
}

func createDataMerkleTree(userData map[string]string, seed string) *MerkleTree {
	var dataHashes [][]byte
	dataHashes = append(dataHashes, addSalt(userData["name"], seed, 0))
	dataHashes = append(dataHashes, addSalt(userData["birthdate"], seed, 1))
	dataHashes = append(dataHashes, addSalt(userData["address"], seed, 2))
	dataHashes = append(dataHashes, addSalt(userData["id"], seed, 3))
	return NewMerkleTree(dataHashes)
}

func createAgeMerkleTree(birthYear int, seed string) *MerkleTree {
	var ageHashes [][]byte
	for i := birthYear; i <= birthYear+18; i++ {
		ageHashes = append(ageHashes, addSalt(strconv.Itoa(i), seed, i-birthYear))
	}
	ageHashes = append(ageHashes, addSalt("<"+strconv.Itoa(birthYear), seed, -1))
	ageHashes = append(ageHashes, addSalt(">"+strconv.Itoa(birthYear+18), seed, -2))
	return NewMerkleTree(ageHashes)
}

func signData(priv *ecdsa.PrivateKey, data []byte) string {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		panic(err)
	}
	signature := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(signature)
}

func verifySignature(pub *ecdsa.PublicKey, data []byte, signature string) bool {
	sig, err := hex.DecodeString(signature)
	if err != nil || len(sig) < 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:len(sig)/2])
	s := new(big.Int).SetBytes(sig[len(sig)/2:])
	hash := sha256.Sum256(data)
	return ecdsa.Verify(pub, hash[:], r, s)
}

// 使用Merkle树的VC
func issueVCWithMerkle(issuerPriv *ecdsa.PrivateKey, userData map[string]string, userDID string) *VerifiableCredential {
	dataSeed := generateSeed()
	ageSeed := generateSeed()
	dataTree := createDataMerkleTree(userData, dataSeed)
	ageTree := createAgeMerkleTree(2000, ageSeed)

	credentialSubject := map[string]interface{}{
		"id": userDID,
		"info": map[string]interface{}{
			"data": userData,
			"birthYearAssert": map[string]interface{}{
				"min":        2000,
				"max":        2018,
				"otherRange": "Both",
				"assert":     []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18},
				"format":     "{0}:{1}",
				"seed":       ageSeed,
				"merkleRoot": hex.EncodeToString(ageTree.RootNode.Data),
			},
			"merkleRoot":    hex.EncodeToString(dataTree.RootNode.Data),
			"rootSignature": signData(issuerPriv, dataTree.RootNode.Data),
			"seed":          dataSeed,
		},
	}

	birthYearAssert := credentialSubject["info"].(map[string]interface{})["birthYearAssert"].(map[string]interface{})
	birthYearAssert["rootSignature"] = signData(issuerPriv, ageTree.RootNode.Data)

	vc := &VerifiableCredential{
		Context:        "https://www.w3.org/2018/credentials/v1",
		ID:             "urn:uuid:bd56a3c4-5be3-4c23-b4a5-878a59b7a013",
		Type:           []string{"VerifiableCredential", "UniversityDegreeCredential"},
		Issuer:         "did:issuer:" + crypto.PubkeyToAddress(issuerPriv.PublicKey).Hex(),
		IssuanceDate:   time.Now().Format(time.RFC3339),
		ExpirationDate: "2026-01-01",
		CredentialSubject: map[string]interface{}{
			"id":   userDID,
			"info": credentialSubject["info"],
		},
	}

	//vcBytes, _ := json.Marshal(vc)
	vc.Proof = Proof{
		Type:               "Secp256k1",
		Created:            time.Now().Format(time.RFC3339),
		VerificationMethod: vc.Issuer + "#key-1",
		Cryptosuite:        "ecdsa-rdfc-2019",
		ProofPurpose:       "assertionMethod",
	}
	vcCopy := *vc
	vcCopy.Proof.ProofValue = "" // 清空签名字段
	vcBytes, _ := json.Marshal(vcCopy)
	vc.Proof.ProofValue = signData(issuerPriv, vcBytes)
	return vc
}

// 不使用Merkle树的简单VC
func issueSimpleVC(issuerPriv *ecdsa.PrivateKey, userData map[string]interface{}, userDID string) *VerifiableCredential {
	vc := &VerifiableCredential{
		Context:        "https://www.w3.org/2018/credentials/v1",
		ID:             "urn:uuid:" + generateSeed(),
		Type:           []string{"VerifiableCredential", "SimpleIdentityCredential"},
		Issuer:         "did:simpleissuer:" + crypto.PubkeyToAddress(issuerPriv.PublicKey).Hex(),
		IssuanceDate:   time.Now().Format(time.RFC3339),
		ExpirationDate: "2026-01-01",
		CredentialSubject: map[string]interface{}{
			"id":          userDID,
			"simpleData":  userData,
			"description": "This is a simple VC without Merkle tree",
		},
	}

	//vcBytes, _ := json.Marshal(vc)
	vc.Proof = Proof{
		Type:               "Secp256k1",
		Created:            time.Now().Format(time.RFC3339),
		VerificationMethod: vc.Issuer + "#key-1",
		Cryptosuite:        "ecdsa-rdfc-2019",
		ProofPurpose:       "assertionMethod",
	}
	vcCopy := *vc
	vcCopy.Proof.ProofValue = "" // 清空签名字段
	vcBytes, _ := json.Marshal(vcCopy)
	vc.Proof.ProofValue = signData(issuerPriv, vcBytes)
	return vc
}

func issueVP(userPriv *ecdsa.PrivateKey, vcs []*VerifiableCredential) *VerifiablePresentation {
	var vcList []VerifiableCredential
	var claimSubjects []map[string]interface{}

	for _, vc := range vcs {
		vcList = append(vcList, *vc)

		// 为每个VC创建对应的claimSubject
		if strings.Contains(vc.Type[1], "UniversityDegree") {
			// 处理使用Merkle树的VC
			birthYear := 2000
			info := vc.CredentialSubject["info"].(map[string]interface{})
			birthYearAssert := info["birthYearAssert"].(map[string]interface{})
			ageSeed := birthYearAssert["seed"].(string)
			merkleRoot := birthYearAssert["merkleRoot"].(string)
			rootSignature := birthYearAssert["rootSignature"].(string)
			format := birthYearAssert["format"].(string)

			currentYear := time.Now().Year()
			age := currentYear - birthYear

			var assertStr string
			if age > 18 {
				assertStr = strings.ReplaceAll(format, "{0}", strconv.Itoa(currentYear))
				assertStr = strings.ReplaceAll(assertStr, "{1}", ">18")
			} else {
				assertStr = fmt.Sprintf(format, currentYear, strconv.Itoa(age))
			}

			salt := addSalt(strconv.Itoa(birthYear+age), ageSeed, age)
			merklesibling := []string{}

			claimSubjects = append(claimSubjects, map[string]interface{}{
				"assert":        assertStr,
				"dataIndex":     age,
				"salt":          hex.EncodeToString(salt),
				"merklesibling": strings.Join(merklesibling, " "),
				"merkleRoot":    merkleRoot,
				"rootSignature": rootSignature,
				"userDid":       vc.CredentialSubject["id"].(string),
				"issuerDid":     vc.Issuer,
				"vcType":        "MerkleBased",
			})
		} else {
			// 处理简单VC
			claimSubjects = append(claimSubjects, map[string]interface{}{
				"simpleData":  vc.CredentialSubject["simpleData"],
				"description": vc.CredentialSubject["description"],
				"userDid":     vc.CredentialSubject["id"].(string),
				"issuerDid":   vc.Issuer,
				"vcType":      "Simple",
			})
		}
	}

	vp := &VerifiablePresentation{
		Context:              "https://www.w3.org/2018/credentials/v1",
		ID:                   "urn:uuid:" + generateSeed(),
		Type:                 []string{"VerifiablePresentation", "CombinedPresentation"},
		Holder:               vcList[0].CredentialSubject["id"].(string),
		VerifiableCredential: vcList,
		ClaimSubject:         claimSubjects,
	}

	vp.Proof = Proof{
		Type:               "Secp256k1",
		Created:            time.Now().Format(time.RFC3339),
		VerificationMethod: vp.Holder + "#key-1",
		Cryptosuite:        "ecdsa-rdfc-2019",
		ProofPurpose:       "authentication",
	}

	vpCopy := *vp
	vpCopy.Proof.ProofValue = ""
	vpBytes, _ := json.Marshal(vpCopy)
	vp.Proof.ProofValue = signData(userPriv, vpBytes)
	return vp
}

func verifyVP(vp *VerifiablePresentation, issuerPubs map[string]*ecdsa.PublicKey, userPub *ecdsa.PublicKey) bool {
	// 验证VP签名
	vpCopy := *vp
	signature := vpCopy.Proof.ProofValue
	vpCopy.Proof.ProofValue = ""
	vpBytes, _ := json.Marshal(vpCopy)
	if !verifySignature(userPub, vpBytes, signature) {
		fmt.Println("VP签名验证失败")
		return false
	}

	// 验证每个VC
	for i, vc := range vp.VerifiableCredential {
		// 获取对应的issuer公钥
		issuerPub, ok := issuerPubs[vc.Issuer]
		if !ok {
			fmt.Printf("未知的发行方: %s\n", vc.Issuer)
			return false
		}

		// 验证VC签名
		vcCopy := vc
		vcSignature := vcCopy.Proof.ProofValue
		vcCopy.Proof.ProofValue = ""
		vcBytes, _ := json.Marshal(vcCopy)
		if !verifySignature(issuerPub, vcBytes, vcSignature) {
			fmt.Printf("VC %d 签名验证失败\n", i)
			return false
		}

		// 如果是Merkle树类型的VC，验证Merkle Root签名
		if vp.ClaimSubject[i]["vcType"] == "MerkleBased" {
			merkleRoot := vp.ClaimSubject[i]["merkleRoot"].(string)
			rootSignature := vp.ClaimSubject[i]["rootSignature"].(string)

			merkleRootBytes, err := hex.DecodeString(merkleRoot)
			if err != nil {
				fmt.Printf("VC %d Merkle Root 解码失败\n", i)
				return false
			}

			if !verifySignature(issuerPub, merkleRootBytes, rootSignature) {
				fmt.Printf("VC %d Merkle Root 签名验证失败\n", i)
				return false
			}
		}
	}

	fmt.Println("VP验证通过")
	for i, claim := range vp.ClaimSubject {
		if claim["vcType"] == "MerkleBased" {
			fmt.Printf("VC %d 断言内容: %s\n", i, claim["assert"])
		} else {
			fmt.Printf("VC %d 简单数据: %v\n", i, claim["simpleData"])
		}
	}
	return true
}

func main() {
	// 创建两个不同的发证方
	issuer1Priv, _ := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	issuer2Priv, _ := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	userPriv, _ := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)

	// 第一个VC使用Merkle树
	userData1 := map[string]string{
		"name":      "张三",
		"birthdate": "2000-01-01",
		"address":   "北京海淀区",
		"id":        "110101200001010011",
	}
	vc1 := issueVCWithMerkle(issuer1Priv, userData1, "did:user:"+crypto.PubkeyToAddress(userPriv.PublicKey).Hex())

	// 第二个VC不使用Merkle树
	userData2 := map[string]interface{}{
		"email":      "zhangsan@example.com",
		"membership": "gold",
		"since":      "2018-05-01",
	}
	vc2 := issueSimpleVC(issuer2Priv, userData2, "did:user:"+crypto.PubkeyToAddress(userPriv.PublicKey).Hex())

	// 生成包含两个VC的VP
	vp := issueVP(userPriv, []*VerifiableCredential{vc1, vc2})

	// 打印结果
	vc1JSON, _ := json.MarshalIndent(vc1, "", "  ")
	fmt.Println("VC1内容 (使用Merkle树):")
	fmt.Println(string(vc1JSON))

	vc2JSON, _ := json.MarshalIndent(vc2, "", "  ")
	fmt.Println("\nVC2内容 (简单VC):")
	fmt.Println(string(vc2JSON))

	vpJSON, _ := json.MarshalIndent(vp, "", "  ")
	fmt.Println("\nVP内容 (包含两个VC):")
	fmt.Println(string(vpJSON))

	// 验证VP
	fmt.Println("\n验证VP:")
	issuerPubs := map[string]*ecdsa.PublicKey{
		vc1.Issuer: &issuer1Priv.PublicKey,
		vc2.Issuer: &issuer2Priv.PublicKey,
	}
	verifyVP(vp, issuerPubs, &userPriv.PublicKey)
}
