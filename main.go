package main

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"time"

	//kmscrypto "github.com/hyperledger/aries-framework-go/component/kmscrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

func main() {
	// 1. 生成 Ed25519 密钥对
	//pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	//signer := kmscrypto.NewEd25519Signer(priv)

	issuerDID := "did:example:issuer"
	holderDID := "did:example:holder"

	// 2. 构造 VC
	vc := verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		ID:    "http://example.edu/credentials/1872",
		Types: []string{"VerifiableCredential"},
		Issuer: verifiable.Issuer{
			ID: issuerDID,
			//CustomFields: nil,
		},
		Issued: util.NewTime(time.Now()),
		Subject: map[string]interface{}{
			"id":   holderDID,
			"name": "Alice",
		},
	}

	//vc, err := verifiable.Credential //NewCredential
	//if err != nil {
	//	panic(err)
	//}

	// 3. VC 签名（JWT）
	signer, err := signature.NewSigner(kms.ED25519Type)
	if err != nil {
		panic(err)
	}
	//vcJWT, err := vc.JWT(vc.Issuer.ID, signer)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("VC JWT:\n", vcJWT)

	// 4. 生成 VP（包含 VC）
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(&vc))
	if err != nil {
		panic(err)
	}
	vp.Holder = holderDID

	// 5. VP 签名（JWT）
	//vpJWT, err := vp.JWT(holderDID, signer)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("\nVP JWT:\n", vpJWT)

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		panic(err)
	}

	// 6. 验证 VC
	parsedVC, err := verifiable.ParseCredential([]byte(vcBytes), verifiable.WithPublicKeyFetcher(
		verifiable.SingleKey(signer.PublicKeyBytes(), string(kms.ED25519Type))))
	if err != nil {
		fmt.Println("VC 验证失败:", err)
	} else {
		b, _ := json.MarshalIndent(parsedVC, "", "  ")
		fmt.Println("\nVC 验证成功:\n", string(b))
	}
	vpBytes, err := vp.MarshalJSON()
	if err != nil {
		panic(err)
	}

	// 7. 验证 VP
	parsedVP, err := verifiable.ParsePresentation([]byte(vpBytes), verifiable.WithPresPublicKeyFetcher(
		verifiable.SingleKey(signer.PublicKeyBytes(), string(kms.ED25519Type))))
	if err != nil {
		fmt.Println("VP 验证失败:", err)
	} else {
		b, _ := json.MarshalIndent(parsedVP, "", "  ")
		fmt.Println("\nVP 验证成功:\n", string(b))
	}
}
