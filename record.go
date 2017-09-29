package bitmarklib

type Record interface {
	ClaimedBy(key AuthKey)
}
