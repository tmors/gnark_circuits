package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"log"
)

type ZkLoginCircuit struct {
	Jwt    frontend.Variable `gnark:"jwt"`
	PubKey frontend.Variable `gnark:",public"`
}

func (circuit *ZkLoginCircuit) Define(api frontend.API) error {
	//x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	//api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))

	return nil
}

func main() {
	// 示例 JWT（请替换为实际的 JWT）
	tokenString := "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE5MzI4NDkyNjgsImlhdCI6MTczMjg0OTI2OCwic3ViIjoic3ViIiwiYXVkIjoiYXVkIiwiaXNzIjoiaXNzIiwiZW1haWwiOiJlbWFpbCIsIm5hbWUiOiJuYW1lIn0.TxOEkjetS1rbMzFKYDtL1Xlh0vjVYgh09rTlAj1jZpXUyTLSXShVSVpLgi487i0Ku9aMAgttfNd4zsSg7EAZzVMuEwrWxWXjhhgocLRYzrC2A7lTzvPWcprYQAx1ac1z865YmQfwOzvUEmcm1vStP0LvaK_x24ytOwUjLDtt8nuVhg3djQuC5LkkEXIMoiLj0XnX5sYgwJALKQ21gRpmTekowLi5KnXOcgXG4xDRhBicTFdUxUwR-I72FT83VPkZb8Lm2JgF2B25H8A-wWGOK_rM2QNHAHTgZC7jBTSR8zEGM1AtTRlg_zPcVCjU0xDKBPyOhJuoVaoLveCpIrGEEAjUD7QHIu8jSzyguF_1_XI-zkuw_g4LaPM4lPeTK0h21IYZRBxg4_KIdo8OuqmSCV4brU4Sqj6sgwxY-1eaX0HlEwWV5DnjjVZH9BkbN2m3yMPH9dBHZX-BJskFfRMuQA9RjNMxCDK16K8v457Vo2ul48hujTprgiy20gzB9V4K" // 省略

	// 示例 JWK（直接使用单个公钥）
	jwkJSON := `{
      "alg": "RS256",
      "e": "AQAB",
      "key_ops": [
        "verify"
      ],
      "kty": "RSA",
      "n": "zcQwXx3EevOSkfH0VSWqtfmWTL4c2oIzW6u83qKO1W7XjLgTqpryL5vNCaxbVTkpU-GZctit0n6kj570tfny_sy6pb2q9wlvFBmDVyD-nL5oNjP5s3qEfvy15Bl9vMGFf3zycqMaVg_7VRVwK5d8QzpnVC0AGT10QdHnyGCadfPJqazTuVRp1f3ecK7bg7596sgVb8d9Wpaz2XPykQPfphsEb40vcp1tPN95-eRCgA24PwfUaKYHQQFMEQY_atJWbffyJ91zsBRy8fEQdfuQVZIRVQgO7FTsmLmQAHxR1dl2jP8B6zonWmtqWoMHoZfa-kmTPB4wNHa8EaLvtQ1060qYFmQWWumfNFnG7HNq2gTHt1cN1HCwstRGIaU_ZHubM_FKH_gLfJPKNW0KWML9mQQzf4AVov0Yfvk89WxY8ilSRx6KodJuIKKqwVh_58PJPLmBqszEfkTjtyxPwP8X8xRXfSz-vTU6vESCk3O6TRknoJkC2BJZ_ONQ0U5dxLcx",
      "use": "sig",
      "kid": "6ab0e8e4bc121fc287e35d3e5e0efb8a"
    }`

	// 解析 JWK
	set, err := jwk.ParseString(jwkJSON)
	if err != nil {
		log.Fatalf("解析 JWK 失败: %v", err)
	}

	key, _ := set.LookupKeyID("6ab0e8e4bc121fc287e35d3e5e0efb8a")

	//// 提取公钥
	publicKey, err := key.PublicKey()
	if err != nil {
		log.Fatalf("提取公钥失败: %v", err)
	}

	token, err := jwt.Parse([]byte(tokenString), jwt.WithValidate(true), jwt.WithKey(jwa.RS256, publicKey))
	if err != nil {
		fmt.Printf("failed to parse JWT token: %s\n", err)
		return
	}

	fmt.Println(token)

	var circuit ZkLoginCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Errorf("compile error: %w", err))
	}

	// Setup 生成keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(fmt.Errorf("setup error: %w", err))
	}

	// 保存 keys
	err = saveKeys(pk, vk, "proving.key", "verifying.key")
	if err != nil {
		panic(fmt.Errorf("save keys error: %w", err))
	}
	fmt.Println("Keys saved successfully")

	assignment := ZkLoginCircuit{tokenString, publicKey}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(fmt.Errorf("witness error: %w", err))
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(fmt.Errorf("public witness error: %w", err))
	}

	// 生成 proof
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(fmt.Errorf("prove error: %w", err))
	}

	// 保存 proof
	err = saveProof(proof, "proof.data")
	if err != nil {
		panic(fmt.Errorf("save proof error: %w", err))
	}
	fmt.Println("Proof saved successfully")

	// 从文件加载 proof 和 keys 进行验证
	loadedProof, err := loadProof("proof.data")
	if err != nil {
		panic(fmt.Errorf("load proof error: %w", err))
	}

	_, loadedVk, err := loadKeys("proving.key", "verifying.key")
	if err != nil {
		panic(fmt.Errorf("load keys error: %w", err))
	}

	// 验证
	err = groth16.Verify(loadedProof, loadedVk, publicWitness)
	if err != nil {
		panic(fmt.Errorf("verify error: %w", err))
	}
	fmt.Println("Proof verified successfully!")
}
