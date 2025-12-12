package nbi2

import (
	"context"
	"database/sql"

	"github.com/caddyserver/certmagic"
)

type CertDatabaseStorage struct {
	DB *sql.DB
	Dialect string
	ErrorCode func(error) string
}

var _ certmagic.Storage = &CertDatabaseStorage{}

func (storage *CertDatabaseStorage) Lock(ctx context.Context, name string) error {
	return nil
}

func (storage *CertDatabaseStorage) Unlock(ctx context.Context, name string) error {
	return nil
}

func (storage *CertDatabaseStorage) Store(ctx context.Context, key string, value []byte) error {
	return nil
}

func (storage *CertDatabaseStorage) Load(ctx context.Context, key string) ([]byte, error) {
	return nil, nil
}

func (storage *CertDatabaseStorage) Delete(ctx context.Context, key string) error {
	return nil
}

func (storage *CertDatabaseStorage) Exists(ctx context.Context, key string) bool {
	return false
}

func (storage *CertDatabaseStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	return nil, nil
}

func (storage *CertDatabaseStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return certmagic.KeyInfo{}, nil
}
