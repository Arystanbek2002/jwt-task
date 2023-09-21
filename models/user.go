package models

import "time"

type User struct {
	Guid          string    `bson:"_id"`
	RefreshToken  string    `bson:"refresh_token"`
	RefreshFamily []string  `bson:"refresh_family"`
	ExpiresAt     time.Time `bson:"expires_at"`
}
