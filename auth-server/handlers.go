package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func signupHandler(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	// Check if user already exists
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	var existingUser User
	err := usersColl.FindOne(ctx, bson.M{"email": req.Email}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, ErrorResponse{
			Error:   "user_exists",
			Message: "User with this email already exists",
		})
		return
	}

	// Hash Password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "server_error",
			Message: "Failed to process password",
		})
		return
	}

	// Create New User
	user := User{
		Email:     req.Email,
		Password:  string(hashedPassword),
		FirstName: req.FirstName,
		LastName:  req.LastName,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result, err := usersColl.InsertOne(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "database_error",
			Message: "Failed to create user",
		})
		return
	}

	user.ID = result.InsertedID.(primitive.ObjectID)

	// Generate JWT Token
	token, err := generateJWT(user.ID.Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "token_error",
			Message: "Failed to generate authentication token",
		})
		return
	}

	c.JSON(http.StatusCreated, LoginResponse{
		User:  user,
		Token: token,
	})
}

func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	// Find user by email
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	var user User
	err := usersColl.FindOne(ctx, bson.M{"email": req.Email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "invalid_credentials",
				Message: "Invalid email or password",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "database_error",
			Message: "Failed to authenticate user",
		})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid email or password",
		})
		return
	}

	// Generate JWT token
	token, err := generateJWT(user.ID.Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "token_error",
			Message: "Failed to generate authentication token",
		})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		User:  user,
		Token: token,
	})
}

func getReportsHandler(c *gin.Context) {	
	userID := c.GetString("userID")

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	var reports []Report
	filter := bson.M{"user_id": userID}
	cursor, err := reportsColl.Find(ctx, filter)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "no_report_found",
				Message: "No report found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "database_error",
			Message: "Failed to fetch user reports",
		})
		return
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var report Report
		if err := cursor.Decode(&report); err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "database_error",
				Message: "Failed to decode report",
			})
			return
		}
		reports = append(reports, report)
	}

	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "database_error",
			Message: "Failed to fetch user reports",
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Reports fetched successfully",
		Data:    reports,
	})
}