# `storage` — Encrypted API Key Storage for Zayry

This Go package provides secure storage and retrieval of model API keys (e.g., OpenAI, Anthropic) for both users and workspaces in the Zayry (Zmesh) platform. It uses AES-256-GCM encryption and stores keys in a PostgreSQL table (`user_api_keys`), scoped either to an individual user or the entire workspace.

## 🔐 Features

- AES-256-GCM encryption for API keys using a 32-byte secret from environment variables
- Supports:
  - User-level API keys (per user per workspace)
  - Workspace-level API keys (shared across workspace members)
- Smart fallback logic: uses workspace key if present, else user key
- Full CRUD: Store, Retrieve, Delete, List
- Backward-compatible helper functions for default workspaces

---

## 📦 Schema

All keys are stored in the same table: `user_api_keys`

| Column              | Type      | Notes                                  |
| ------------------- | --------- | -------------------------------------- |
| `id`                | UUID      | Primary key                            |
| `user_id`           | UUID      | `uuid.Nil` for workspace keys          |
| `workspace_id`      | UUID      | Workspace-scoped                       |
| `model`             | TEXT      | Model identifier (e.g. `openai/gpt-4`) |
| `api_key_encrypted` | BYTEA     | AES-256-GCM encrypted API key          |
| `created_at`        | TIMESTAMP | Auto-managed                           |
| `updated_at`        | TIMESTAMP | (Optional) For version tracking        |

---

## 🔧 Environment Variable

```env
API_KEY_ENCRYPTION_KEY=32-byte-long-secret-key-value-here
```

Must be exactly 32 bytes. It is used as the AES encryption key.

---

## 🔐 Encryption Design

- Uses `crypto/aes` and `cipher.NewGCM` for authenticated encryption
- Encrypts using a unique nonce per key
- Stores `nonce + ciphertext` together in a single blob
- Decrypts with key from environment and nonce extracted from blob

---

## ✅ Functions

### 🔑 User-level API Key Functions

```go
StoreUserAPIKey(db, userID, workspaceID, model, apiKey)
GetUserAPIKey(db, userID, workspaceID, model)
DeleteUserAPIKey(db, userID, workspaceID, model)
ListUserAPIKeyModels(db, userID, workspaceID)
```

### 🧑‍💻 Backward Compatibility Wrappers

Assumes user's default workspace:

```go
StoreUserAPIKeyCompat(db, userID, model, apiKey)
GetUserAPIKeyCompat(db, userID, model)
DeleteUserAPIKeyCompat(db, userID, model)
ListUserAPIKeyModelsCompat(db, userID)
```

### 🏢 Workspace-level API Key Functions

Shared for all users in the workspace:

```go
StoreWorkspaceAPIKey(db, workspaceID, model, apiKey)
GetWorkspaceAPIKey(db, workspaceID, model)
DeleteWorkspaceAPIKey(db, workspaceID, model)
ListWorkspaceAPIKeyModels(db, workspaceID)
```

### ⚙️ Execution Fallback

Automatically checks for workspace key first, then falls back to user key.

```go
GetAPIKeyForExecution(db, userID, workspaceID, model)
```

---

## 🧪 Example

```go
// Store a workspace-level API key
err := StoreWorkspaceAPIKey(db, workspaceID, "openai/gpt-4", "sk-1234...")
if err != nil {
	log.Fatal(err)
}

// Retrieve the best key for execution (workspace > user fallback)
key, err := GetAPIKeyForExecution(db, userID, workspaceID, "openai/gpt-4")
```

---

## 🛡️ Security Notes

- No plaintext keys are ever stored
- Encryption key is never hardcoded — loaded from environment
- Only AES-256-GCM is used (authenticated encryption with nonce)
- Table is shared for both user and workspace keys, differentiated by `user_id = uuid.Nil`

---
