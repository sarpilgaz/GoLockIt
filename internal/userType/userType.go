package userType

type User struct {
	Uid           int64
	Name          string
	Salt          []byte
	MasterKeyHash []byte
}
