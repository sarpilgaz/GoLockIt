package userType

type User struct {
	uid           uint8
	name          string
	salt          string
	masterKeyHash string
}
