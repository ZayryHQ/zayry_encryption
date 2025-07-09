package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ZayryHQ/Zmesh/api/env"
	"github.com/google/uuid"
)

// UserAPIKey represents a row in user_api_keys
type UserAPIKey struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	WorkspaceID     uuid.UUID
	Model           string
	APIKeyEncrypted []byte
	CreatedAt       time.Time
}

// WorkspaceAPIKey represents a workspace-level API key
type WorkspaceAPIKey struct {
	ID              uuid.UUID
	WorkspaceID     uuid.UUID
	Model           string
	APIKeyEncrypted []byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func getEncryptionKey() ([]byte, error) {
	key := env.APIKeyEncryptionKey
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	return []byte(key), nil
}

func encryptAPIKey(plainText string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)
	return ciphertext, nil
}

func decryptAPIKey(ciphertext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plain, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func StoreUserAPIKey(db *sql.DB, userID, workspaceID uuid.UUID, model, apiKey string) error {
	key, err := getEncryptionKey()
	if err != nil {
		return err
	}
	encrypted, err := encryptAPIKey(apiKey, key)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO user_api_keys (id, user_id, workspace_id, model, api_key_encrypted)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (user_id, workspace_id, model)
		 DO UPDATE SET api_key_encrypted = EXCLUDED.api_key_encrypted, created_at = now()`,
		uuid.New(), userID, workspaceID, model, encrypted,
	)
	return err
}

func GetUserAPIKey(db *sql.DB, userID, workspaceID uuid.UUID, model string) (string, error) {
	var encrypted []byte
	err := db.QueryRow(
		`SELECT api_key_encrypted FROM user_api_keys WHERE user_id = $1 AND workspace_id = $2 AND model = $3`,
		userID, workspaceID, model,
	).Scan(&encrypted)
	if err != nil {
		return "", err
	}
	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	return decryptAPIKey(encrypted, key)
}

// DeleteUserAPIKey deletes an API key for a user/model
func DeleteUserAPIKey(db *sql.DB, userID, workspaceID uuid.UUID, model string) error {
	_, err := db.Exec(`DELETE FROM user_api_keys WHERE user_id = $1 AND workspace_id = $2 AND model = $3`, userID, workspaceID, model)
	return err
}

// ListUserAPIKeyModels returns all models for which the user has an API key
func ListUserAPIKeyModels(db *sql.DB, userID, workspaceID uuid.UUID) ([]map[string]string, error) {
	rows, err := db.Query(`SELECT model FROM user_api_keys WHERE user_id = $1 AND workspace_id = $2`, userID, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var models []map[string]string
	for rows.Next() {
		var model string
		if err := rows.Scan(&model); err != nil {
			return nil, err
		}
		models = append(models, map[string]string{"model": model})
	}
	return models, nil
}

// Backward compatibility wrappers for API key functions
func StoreUserAPIKeyCompat(db *sql.DB, userID uuid.UUID, model, apiKey string) error {
	// Get user's default workspace
	defaultWorkspace, err := GetUserDefaultWorkspace(userID)
	if err != nil {
		return fmt.Errorf("failed to get default workspace: %w", err)
	}
	return StoreUserAPIKey(db, userID, defaultWorkspace.ID, model, apiKey)
}

func GetUserAPIKeyCompat(db *sql.DB, userID uuid.UUID, model string) (string, error) {
	// Get user's default workspace
	defaultWorkspace, err := GetUserDefaultWorkspace(userID)
	if err != nil {
		return "", fmt.Errorf("failed to get default workspace: %w", err)
	}
	return GetUserAPIKey(db, userID, defaultWorkspace.ID, model)
}

func DeleteUserAPIKeyCompat(db *sql.DB, userID uuid.UUID, model string) error {
	// Get user's default workspace
	defaultWorkspace, err := GetUserDefaultWorkspace(userID)
	if err != nil {
		return fmt.Errorf("failed to get default workspace: %w", err)
	}
	return DeleteUserAPIKey(db, userID, defaultWorkspace.ID, model)
}

func ListUserAPIKeyModelsCompat(db *sql.DB, userID uuid.UUID) ([]map[string]string, error) {
	// Get user's default workspace
	defaultWorkspace, err := GetUserDefaultWorkspace(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get default workspace: %w", err)
	}
	return ListUserAPIKeyModels(db, userID, defaultWorkspace.ID)
}

// New workspace-level API key functions

// StoreWorkspaceAPIKey stores an encrypted API key for a workspace
func StoreWorkspaceAPIKey(db *sql.DB, workspaceID uuid.UUID, model, apiKey string) error {
	key, err := getEncryptionKey()
	if err != nil {
		return err
	}
	encrypted, err := encryptAPIKey(apiKey, key)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO user_api_keys (id, user_id, workspace_id, model, api_key_encrypted, created_at)
		 VALUES ($1, $2, $3, $4, $5, now())
		 ON CONFLICT (user_id, workspace_id, model)
		 DO UPDATE SET api_key_encrypted = EXCLUDED.api_key_encrypted, created_at = now()`,
		uuid.New(), uuid.Nil, workspaceID, model, encrypted,
	)
	return err
}

// GetWorkspaceAPIKey retrieves an API key for a workspace and model
func GetWorkspaceAPIKey(db *sql.DB, workspaceID uuid.UUID, model string) (string, error) {
	var encrypted []byte
	err := db.QueryRow(
		`SELECT api_key_encrypted FROM user_api_keys WHERE user_id = $1 AND workspace_id = $2 AND model = $3`,
		uuid.Nil, workspaceID, model,
	).Scan(&encrypted)
	if err != nil {
		return "", err
	}
	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	return decryptAPIKey(encrypted, key)
}

// DeleteWorkspaceAPIKey deletes an API key for a workspace/model
func DeleteWorkspaceAPIKey(db *sql.DB, workspaceID uuid.UUID, model string) error {
	_, err := db.Exec(`DELETE FROM user_api_keys WHERE user_id = $1 AND workspace_id = $2 AND model = $3`, uuid.Nil, workspaceID, model)
	return err
}

// ListWorkspaceAPIKeyModels returns all models for which the workspace has an API key
func ListWorkspaceAPIKeyModels(db *sql.DB, workspaceID uuid.UUID) ([]map[string]string, error) {
	rows, err := db.Query(`SELECT model FROM user_api_keys WHERE user_id = $1 AND workspace_id = $2`, uuid.Nil, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var models []map[string]string
	for rows.Next() {
		var model string
		if err := rows.Scan(&model); err != nil {
			return nil, err
		}
		models = append(models, map[string]string{"model": model})
	}
	return models, nil
}

// GetAPIKeyForExecution gets an API key for model execution, trying workspace first then user fallback
func GetAPIKeyForExecution(db *sql.DB, userID, workspaceID uuid.UUID, model string) (string, error) {
	// First try to get workspace-level API key
	apiKey, err := GetWorkspaceAPIKey(db, workspaceID, model)
	if err == nil {
		return apiKey, nil
	}

	return GetUserAPIKey(db, userID, workspaceID, model)
}
