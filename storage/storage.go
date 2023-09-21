package storage

import (
	"context"
	"fmt"

	"github.com/arystanbek2002/jwt-task/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type Storage struct {
	col *mongo.Collection
}

func NewStorage(ctx context.Context, client *mongo.Client) *Storage {
	return &Storage{
		col: client.Database("jwt-task").Collection("users"),
	}
}

func (str *Storage) InsertUser(ctx context.Context, user *models.User) (*mongo.InsertOneResult, error) {
	res, err := str.col.InsertOne(ctx, user)
	if err != nil {
		return nil, err
	}
	return res, err
}

func (str *Storage) UpdateUser(ctx context.Context, user *models.User) (*mongo.UpdateResult, error) {
	filter := bson.D{{"_id", user.Guid}}
	replacement := bson.D{{"refresh_token", user.RefreshToken}, {"refresh_family", user.RefreshFamily}, {"expires_at", user.ExpiresAt}}
	res, err := str.col.ReplaceOne(ctx, filter, replacement)
	if err != nil {
		return nil, err
	}
	return res, err
}

func (str *Storage) GetUser(ctx context.Context, guid string) (*models.User, error) {
	filter := bson.D{{"_id", guid}}
	var user models.User
	err := str.col.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("no such user")
		}
		return nil, err
	}
	return &user, err
}

func (str *Storage) Test(ctx context.Context) ([]models.User, error) {
	res, err := str.col.Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	var result []models.User
	err = res.All(ctx, &result)
	if err != nil {
		return nil, err
	}
	return result, err
}
