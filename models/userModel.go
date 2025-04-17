package models

import "gorm.io/gorm"

type User struct {
	gorm.Model `gorm:"unique"`
	Email      string
	Password   string
}
