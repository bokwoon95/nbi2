package nbi2

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/bokwoon95/sqddl/ddl"
)

//go:embed schema_database.json
var databaseSchemaBytes []byte

type rawTable struct {
	Table      string
	PrimaryKey []string
	Columns    []struct {
		Dialect   string
		Column    string
		Type      map[string]string
		Generated struct {
			Expression string
			Stored     bool
		}
		Index      bool
		PrimaryKey bool
		Unique     bool
		NotNull    bool
		References struct {
			Table  string
			Column string
		}
	}
	Indexes []struct {
		Dialect        string
		Type           string
		Unique         bool
		Columns        []string
		IncludeColumns []string
		Predicate      string
	}
	Constraints []struct {
		Dialect           string
		Type              string
		Columns           []string
		ReferencesTable   string
		ReferencesColumns []string
	}
}

// unmarshalCatalog unmarshals a JSON payload into a *ddl.Catalog.
func unmarshalCatalog(b []byte, catalog *ddl.Catalog) error {
	var rawTables []rawTable
	decoder := json.NewDecoder(bytes.NewReader(b))
	err := decoder.Decode(&rawTables)
	if err != nil {
		return err
	}
	cache := ddl.NewCatalogCache(catalog)
	schema := cache.GetOrCreateSchema(catalog, "")
	for _, rawTable := range rawTables {
		table := cache.GetOrCreateTable(schema, rawTable.Table)
		if len(rawTable.PrimaryKey) != 0 {
			cache.AddOrUpdateConstraint(table, ddl.Constraint{
				ConstraintName: ddl.GenerateName(ddl.PRIMARY_KEY, rawTable.Table, rawTable.PrimaryKey),
				ConstraintType: ddl.PRIMARY_KEY,
				Columns:        rawTable.PrimaryKey,
			})
		}
		for _, rawColumn := range rawTable.Columns {
			columnType := rawColumn.Type[catalog.Dialect]
			if columnType == "" {
				columnType = rawColumn.Type["default"]
			}
			if rawColumn.Dialect != "" && rawColumn.Dialect != catalog.Dialect {
				continue
			}
			cache.AddOrUpdateColumn(table, ddl.Column{
				ColumnName:          rawColumn.Column,
				ColumnType:          columnType,
				IsPrimaryKey:        rawColumn.PrimaryKey,
				IsUnique:            rawColumn.Unique,
				IsNotNull:           rawColumn.NotNull,
				GeneratedExpr:       rawColumn.Generated.Expression,
				GeneratedExprStored: rawColumn.Generated.Stored,
			})
			if rawColumn.PrimaryKey {
				cache.AddOrUpdateConstraint(table, ddl.Constraint{
					ConstraintName: ddl.GenerateName(ddl.PRIMARY_KEY, rawTable.Table, []string{rawColumn.Column}),
					ConstraintType: ddl.PRIMARY_KEY,
					Columns:        []string{rawColumn.Column},
				})
			}
			if rawColumn.Unique {
				cache.AddOrUpdateConstraint(table, ddl.Constraint{
					ConstraintName: ddl.GenerateName(ddl.UNIQUE, rawTable.Table, []string{rawColumn.Column}),
					ConstraintType: ddl.UNIQUE,
					Columns:        []string{rawColumn.Column},
				})
			}
			if rawColumn.Index {
				cache.AddOrUpdateIndex(table, ddl.Index{
					IndexName: ddl.GenerateName(ddl.INDEX, rawTable.Table, []string{rawColumn.Column}),
					Columns:   []string{rawColumn.Column},
				})
			}
			if rawColumn.References.Table != "" {
				columnName := rawColumn.References.Column
				if columnName == "" {
					columnName = rawColumn.Column
				}
				cache.AddOrUpdateConstraint(table, ddl.Constraint{
					ConstraintName:    ddl.GenerateName(ddl.FOREIGN_KEY, rawTable.Table, []string{rawColumn.Column}),
					ConstraintType:    ddl.FOREIGN_KEY,
					Columns:           []string{rawColumn.Column},
					ReferencesTable:   rawColumn.References.Table,
					ReferencesColumns: []string{columnName},
					UpdateRule:        ddl.CASCADE,
				})
			}
		}
		for _, rawIndex := range rawTable.Indexes {
			if rawIndex.Dialect != "" && rawIndex.Dialect != catalog.Dialect {
				continue
			}
			cache.AddOrUpdateIndex(table, ddl.Index{
				IndexName:      ddl.GenerateName(ddl.INDEX, rawTable.Table, rawIndex.Columns),
				IndexType:      rawIndex.Type,
				IsUnique:       rawIndex.Unique,
				Columns:        rawIndex.Columns,
				IncludeColumns: rawIndex.IncludeColumns,
				Predicate:      rawIndex.Predicate,
			})
		}
		for _, rawConstraint := range rawTable.Constraints {
			if rawConstraint.Dialect != "" && rawConstraint.Dialect != catalog.Dialect {
				continue
			}
			if rawConstraint.Type != ddl.PRIMARY_KEY && rawConstraint.Type != ddl.FOREIGN_KEY && rawConstraint.Type != ddl.UNIQUE {
				return fmt.Errorf("%s: invalid constraint type %q", rawTable.Table, rawConstraint.Type)
			}
			cache.AddOrUpdateConstraint(table, ddl.Constraint{
				ConstraintName:    ddl.GenerateName(rawConstraint.Type, rawTable.Table, rawConstraint.Columns),
				ConstraintType:    rawConstraint.Type,
				Columns:           rawConstraint.Columns,
				ReferencesTable:   rawConstraint.ReferencesTable,
				ReferencesColumns: rawConstraint.ReferencesColumns,
			})
		}
	}
	return nil
}
