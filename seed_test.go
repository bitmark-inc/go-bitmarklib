package bitmarklib

import "testing"

func TestSeed(t *testing.T) {
	seed, _ := NewSeed(SeedVersion1, Livenet)

	base58Seed := seed.String()

	seedFromBase58, _ := SeedFromBase58(base58Seed)
	if seedFromBase58.String() != base58Seed {
		t.Fail()
	}
}

func TestInvalidBase58Seed(t *testing.T) {
	_, err := SeedFromBase58("5XEECsYGDXGWmBnSrExALVTWhzj9mNXxs3y98TgrtkLi6GE4qfoam")
	if err != ErrSeedSizeMismatch {
		t.Fail()
	}

	_, err = SeedFromBase58("3XEECsYGDXGWmBnSrExALVTWhzj9mNXxs3y98TgrtkLi6GE4qfoammV")
	if err != ErrSeedHeaderMismatch {
		t.Fail()
	}

	_, err = SeedFromBase58("5XEECsYGDXGWmBnSrExALVTWbitMARK123y98TgrtkLi6GE4qfoammV")
	if err != ErrSeedChecksumMismatch {
		t.Fail()
	}
}
