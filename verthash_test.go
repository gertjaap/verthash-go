package verthash

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

var verthashTestInput []byte
var verthashTestOutput []byte

func TestMain(m *testing.M) {
	fmt.Println("Verthash test vectors require generation of Verthash file, this will be slow!")
	os.Remove("/tmp/verthash_verthash_go_testsuite.dat")
	MakeVerthashDatafile("/tmp/verthash_verthash_go_testsuite.dat")
	verthashTestInput, _ = hex.DecodeString("000000203a297b4b7685170d7644b43e5a6056234cc2414edde454a87580e1967d14c1078c13ea916117b0608732f3f65c2e03b81322efc0a62bcee77d8a9371261970a58a5a715da80e031b02560ad8")
	verthashTestOutput, _ = hex.DecodeString("E0F6C10B4A38F35A6CDCC26D32A7ED8C3BFC5D827A9BC72647AFA324B70D0463")
	code := m.Run()
	os.Remove("/tmp/verthash_verthash_go_testsuite.dat")
	os.Exit(code)
}

func TestCreation(t *testing.T) {
	ok, err := VerifyVerthashDatafile("/tmp/verthash_verthash_go_testsuite.dat")
	if err != nil || !ok {
		t.Error(err)
	}
}

func TestHashDisk(t *testing.T) {
	vh, err := NewVerthash("/tmp/verthash_verthash_go_testsuite.dat", false)
	if err != nil {
		t.Error(err)
	}
	defer vh.Close()

	h, err := vh.SumVerthash(verthashTestInput)
	if !bytes.Equal(h[:], verthashTestOutput) {
		t.Errorf("Verthash output invalid: %x vs %x", h, verthashTestOutput)
	}

}

func TestHashMemory(t *testing.T) {
	vh, err := NewVerthash("/tmp/verthash_verthash_go_testsuite.dat", true)
	if err != nil {
		t.Error(err)
	}
	defer vh.Close()

	h, err := vh.SumVerthash(verthashTestInput)
	if !bytes.Equal(h[:], verthashTestOutput) {
		//os.Remove("/tmp/verthash.dat")
		t.Errorf("Verthash output invalid: %x vs %x", h, verthashTestOutput)
	}
}
