package psiMagic

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/ipfs/bbloom"
)

var (
	DSTExample     = "Quux-V01-CS01-with-XXXX_XMD:SHA-YYY_SSWU_RO_"
	exampleList    []string
	bristexamplepk = []byte{0, 227, 71, 215, 228, 40, 208, 65, 117, 248, 226, 176, 196, 179, 113, 228, 52, 87, 32, 244, 83, 173, 79, 210, 143, 246, 115, 119, 11, 11, 101, 15}
)

func TestMain(m *testing.M) {

	for i := 0; i < 1000; i++ {
		example := fmt.Sprintf("Example %d", i)
		exampleList = append(exampleList, example)
	}

	fmt.Printf("Benchmark for %v elements.\n", len(exampleList))

	os.Exit(m.Run())
}

// m=#Elements Client, n=#Elements Server
// r_{s}= random Number Server, r_c = random Number Client
// c_{i}= Element of Client -> C={c_{1}, c_{2}, ..., c_{m}}
// s_{i}= Element of Server -> S={s_{1}, s_{2}, ..., s_{n}}
// u_{j}=H(s_{j})^{r_{s}} -> U={u_{1}, u_{2}, ..., u_{n}}
// v_{i}= H(c_{i})^{r_{c}} -> V={v_{1}, v_{2}, ..., v_{m}}
// w_{i}= v_{i}^{r_{s}} -> W= {w_{1}, w_{2}, ..., w_{m}}
// x_{i}= w_{i}^{\frac{1}{r_{c}}} -> X= {x_{1}, x_{2}, ..., x_{m}}
func ExamplePsiMage() {

	m := 5
	n := 10

	C := exampleList[:m]
	S := exampleList[:n]

	// Client and Server need to use same DST and Curve
	clientMage, err := CreateWithNewKey(group.Ristretto255, DSTExample)
	if err != nil {
		panic(err)
	}
	serverMage, err := CreateWithNewKey(group.Ristretto255, DSTExample)
	if err != nil {
		panic(err)
	}

	var U, V, W, X [][]byte

	// Server Preparation
	for _, s_i := range S {
		u_i, err := serverMage.Encrypt([]byte(s_i))
		if err != nil {
			panic(err)
		}
		U = append(U, u_i)
	}

	// Client Preparation
	for _, c_i := range C {
		v_i, err := clientMage.Encrypt([]byte(c_i))
		if err != nil {
			panic(err)
		}
		V = append(V, v_i)
	}

	// Client sends V to Server
	for _, v_i := range V {
		w_i, err := serverMage.ReEncrypt(v_i)
		if err != nil {
			panic(err)
		}
		W = append(W, w_i)
	}

	// Server sends W (and U) to Client
	for _, w_i := range W {
		x_i, err := clientMage.Decrypt(w_i)
		if err != nil {
			panic(err)
		}
		X = append(X, x_i)
	}

	// Client checks X and U
	var intersection []string
	for i, x_i := range X {
		for _, u_i := range U {
			if bytes.Equal(x_i, u_i) {
				intersection = append(intersection, C[i])
			}
		}
	}

	fmt.Printf("%v %v %v %v\n", len(C), len(S), len(intersection), intersection)

	// Output: 5 10 5 [Example 0 Example 1 Example 2 Example 3 Example 4]
}

func ExamplePsiMage_withBloom() {

	m := 5
	n := 10

	C := exampleList[:m]
	S := exampleList[:n]

	// Client and Server need to use same DST and Curve
	clientMage, err := CreateWithNewKey(group.Ristretto255, DSTExample)
	if err != nil {
		panic(err)
	}
	serverMage, err := CreateWithNewKey(group.Ristretto255, DSTExample)
	if err != nil {
		panic(err)
	}

	var U, V, W, X [][]byte

	// Server Preparation
	for _, s_i := range S {
		u_i, err := serverMage.Encrypt([]byte(s_i))
		if err != nil {
			panic(err)
		}
		U = append(U, u_i)
	}
	bf, err := bbloom.New(float64(n), 0.03)
	if err != nil {
		panic(err)
	}
	for _, u_i := range U {
		bf.Add(u_i)
	}

	// Client Preparation
	for _, c_i := range C {
		v_i, err := clientMage.Encrypt([]byte(c_i))
		if err != nil {
			panic(err)
		}
		V = append(V, v_i)
	}

	// Client sends V to Server
	for _, v_i := range V {
		w_i, err := serverMage.ReEncrypt(v_i)
		if err != nil {
			panic(err)
		}
		W = append(W, w_i)
	}

	// Server sends W (and BF) to Client
	for _, w_i := range W {
		x_i, err := clientMage.Decrypt(w_i)
		if err != nil {
			panic(err)
		}
		X = append(X, x_i)
	}

	// Client checks X and BF
	var intersection []string
	for i, x_i := range X {
		if bf.Has(x_i) {
			intersection = append(intersection, C[i])
		}
	}

	fmt.Printf("%v %v %v %v\n", len(C), len(S), len(intersection), intersection)

	// Output: 5 10 5 [Example 0 Example 1 Example 2 Example 3 Example 4]
}

func TestM_CreateWithNewKey(t *testing.T) {
	_, err := CreateWithNewKey(group.Ristretto255, DSTExample)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreateWithNewKey(group.P256, DSTExample)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreateWithNewKey(group.P384, DSTExample)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreateWithNewKey(group.P521, DSTExample)
	if err != nil {
		t.Fatal(err)
	}
	var unknowngroup group.Group
	_, err = CreateWithNewKey(unknowngroup, "")
	if err == nil {
		t.Fatal()
	}
}

func TestM_CreateFromKey(t *testing.T) {
	ristexamplepk := group.Ristretto255.NewScalar()
	err := ristexamplepk.UnmarshalBinary(bristexamplepk)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CreateFromKey(group.Ristretto255, DSTExample, ristexamplepk)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CreateFromKey(group.P256, DSTExample, ristexamplepk)
	if err != group.ErrType {
		t.Fatal(err)
	}
}

func TestM_Encryption(t *testing.T) {
	ristexamplepk := group.Ristretto255.NewScalar()
	err := ristexamplepk.UnmarshalBinary(bristexamplepk)
	if err != nil {
		t.Fatal(err)
	}
	ecExample, err := CreateFromKey(group.Ristretto255, DSTExample, ristexamplepk)
	if err != nil {
		t.Fatal()
	}
	enccid, err := ecExample.Encrypt([]byte("Test"))
	if err != nil {
		t.Fatal(err)
	}
	renccid, err := ecExample.ReEncrypt(enccid)
	if err != nil {
		t.Fatal()
	}
	deccid, err := ecExample.Decrypt(renccid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enccid, deccid) {
		t.Fatal("Error in the encryption process.")
	}
}

func benchEncrypt(b *testing.B, g group.Group) {
	mage, err := CreateWithNewKey(g, DSTExample)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for r := 0; r < b.N; r++ {
		for _, str := range exampleList {
			_, _ = mage.Encrypt([]byte(str))
		}
	}
}

func benchReEncrypt(b *testing.B, g group.Group) {
	mage, err := CreateWithNewKey(g, DSTExample)
	if err != nil {
		b.Fatal(err)
	}

	var encList []string
	for _, str := range exampleList {
		encb, err := mage.Encrypt([]byte(str))
		if err != nil {
			b.Fatal(err)
		}
		encList = append(encList, string(encb))
	}

	b.ResetTimer()
	for r := 0; r < b.N; r++ {
		for _, str := range encList {
			_, _ = mage.ReEncrypt([]byte(str))
		}
	}
}

func benchDecrypt(b *testing.B, g group.Group) {
	mage, err := CreateWithNewKey(g, DSTExample)
	if err != nil {
		b.Fatal(err)
	}

	var encList []string
	for _, str := range exampleList {
		encb, err := mage.Encrypt([]byte(str))
		if err != nil {
			b.Fatal(err)
		}
		encList = append(encList, string(encb))
	}
	b.ResetTimer()
	for r := 0; r < b.N; r++ {
		for _, str := range encList {
			_, _ = mage.Decrypt([]byte(str))
		}
	}
}

func BenchmarkM_Rist_Encrypt(b *testing.B) {
	benchEncrypt(b, group.Ristretto255)
}

func BenchmarkM_P256_Encrypt(b *testing.B) {
	benchEncrypt(b, group.P256)
}

func BenchmarkM_P384_Encrypt(b *testing.B) {
	benchEncrypt(b, group.P384)
}

func BenchmarkM_P521_Encrypt(b *testing.B) {
	benchEncrypt(b, group.P521)
}

func BenchmarkM_Rist_ReEncrypt(b *testing.B) {
	benchReEncrypt(b, group.Ristretto255)
}

func BenchmarkM_P256_ReEncrypt(b *testing.B) {
	benchReEncrypt(b, group.P256)
}

func BenchmarkM_P384_ReEncrypt(b *testing.B) {
	benchReEncrypt(b, group.P384)
}

func BenchmarkM_P521_ReEncrypt(b *testing.B) {
	benchReEncrypt(b, group.P521)
}

func BenchmarkM_Rist_Decrypt(b *testing.B) {
	benchDecrypt(b, group.Ristretto255)
}

func BenchmarkM_P256_Decrypt(b *testing.B) {
	benchDecrypt(b, group.P256)
}

func BenchmarkM_P384_Decrypt(b *testing.B) {
	benchDecrypt(b, group.P384)
}

func BenchmarkM_P521_Decrypt(b *testing.B) {
	benchDecrypt(b, group.P521)
}
