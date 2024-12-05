package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"os"
)

// SimpleCircuit defines a simple circuit
// x**3 + x + 5 == y
type SimpleCircuit struct {
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *SimpleCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

// saveProof 保存proof到文件
func saveProof(proof groth16.Proof, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create proof file: %w", err)
	}
	defer file.Close()

	_, err = proof.WriteRawTo(file)
	if err != nil {
		return fmt.Errorf("failed to write proof: %w", err)
	}
	return nil
}

// loadProof 从文件加载proof
func loadProof(path string) (groth16.Proof, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	defer file.Close()

	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof: %w", err)
	}
	return proof, nil
}

// saveKeys 保存proving key和verification key
func saveKeys(pk groth16.ProvingKey, vk groth16.VerifyingKey, pkPath, vkPath string) error {
	// 保存 proving key
	pkFile, err := os.Create(pkPath)
	if err != nil {
		return fmt.Errorf("failed to create pk file: %w", err)
	}
	defer pkFile.Close()

	_, err = pk.WriteRawTo(pkFile)
	if err != nil {
		return fmt.Errorf("failed to write pk: %w", err)
	}

	// 保存 verification key
	vkFile, err := os.Create(vkPath)
	if err != nil {
		return fmt.Errorf("failed to create vk file: %w", err)
	}
	defer vkFile.Close()

	_, err = vk.WriteRawTo(vkFile)
	if err != nil {
		return fmt.Errorf("failed to write vk: %w", err)
	}

	return nil
}

// loadKeys 加载proving key和verification key
func loadKeys(pkPath, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	// 加载 proving key
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	defer pkFile.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read pk: %w", err)
	}

	// 加载 verification key
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open vk file: %w", err)
	}
	defer vkFile.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read vk: %w", err)
	}

	return pk, vk, nil
}

//
//func main() {
//	// 编译电路
//	var circuit SimpleCircuit
//	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
//	if err != nil {
//		panic(fmt.Errorf("compile error: %w", err))
//	}
//
//	// Setup 生成keys
//	pk, vk, err := groth16.Setup(ccs)
//	if err != nil {
//		panic(fmt.Errorf("setup error: %w", err))
//	}
//
//	// 保存 keys
//	err = saveKeys(pk, vk, "proving.key", "verifying.key")
//	if err != nil {
//		panic(fmt.Errorf("save keys error: %w", err))
//	}
//	fmt.Println("Keys saved successfully")
//
//	// 创建 witness
//	assignment := SimpleCircuit{X: 3, Y: 35}
//	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
//	if err != nil {
//		panic(fmt.Errorf("witness error: %w", err))
//	}
//
//	publicWitness, err := witness.Public()
//	if err != nil {
//		panic(fmt.Errorf("public witness error: %w", err))
//	}
//
//	// 生成 proof
//	proof, err := groth16.Prove(ccs, pk, witness)
//	if err != nil {
//		panic(fmt.Errorf("prove error: %w", err))
//	}
//
//	// 保存 proof
//	err = saveProof(proof, "proof.data")
//	if err != nil {
//		panic(fmt.Errorf("save proof error: %w", err))
//	}
//	fmt.Println("Proof saved successfully")
//
//	// 从文件加载 proof 和 keys 进行验证
//	loadedProof, err := loadProof("proof.data")
//	if err != nil {
//		panic(fmt.Errorf("load proof error: %w", err))
//	}
//
//	_, loadedVk, err := loadKeys("proving.key", "verifying.key")
//	if err != nil {
//		panic(fmt.Errorf("load keys error: %w", err))
//	}
//
//	// 验证
//	err = groth16.Verify(loadedProof, loadedVk, publicWitness)
//	if err != nil {
//		panic(fmt.Errorf("verify error: %w", err))
//	}
//	fmt.Println("Proof verified successfully!")
//}
