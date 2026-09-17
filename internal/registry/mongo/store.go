// Package mongo stores federated key-derivation commitments in MongoDB.
//
// The registry is the authoritative answer to "who holds a piece of this tenant's
// key material". Two properties matter more than throughput:
//
//   - completeness over time: a destroyed slot keeps its operator key (with empty
//     material) so the destruction quorum stays reconstructable and the verifier
//     can still check "quorum matches registry wraps" after an erasure;
//   - conflict safety: two operators may never register different seeds under the
//     same tenant, so the seed commitment is enforced by a unique index and an
//     atomic conditional update rather than read-modify-write.
package mongo

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"nexqloud-sealed/internal/registry"
)

// ErrSeedCommitConflict means the tenant already commits to a different seed.
var ErrSeedCommitConflict = errors.New("seed_commit mismatch")

// defaultTimeout bounds each registry operation.
const defaultTimeout = 5 * time.Second

type document struct {
	TenantID   string               `bson:"tenant_id"`
	KeyVersion int                  `bson:"key_version"`
	SeedCommit string               `bson:"seed_commit"`
	Wraps      map[string]string    `bson:"wraps"` // base64; "" marks a destroyed slot
	Callbacks  map[string]string    `bson:"callbacks,omitempty"`
	Destroyed  map[string]time.Time `bson:"destroyed_at,omitempty"`
	UpdatedAt  time.Time            `bson:"updated_at"`
}

type Store struct {
	client *mongo.Client
	coll   *mongo.Collection
}

// New connects to MongoDB and prepares the commitments collection.
func New(ctx context.Context, uri, db, collection string) (*Store, error) {
	if strings.TrimSpace(uri) == "" {
		return nil, fmt.Errorf("mongo uri is required")
	}
	if strings.TrimSpace(db) == "" || strings.TrimSpace(collection) == "" {
		return nil, fmt.Errorf("mongo database and collection are required")
	}

	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(connectCtx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("connect mongo: %w", err)
	}
	if err := client.Ping(connectCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongo: %w", err)
	}

	store := &Store{client: client, coll: client.Database(db).Collection(collection)}
	if _, err := store.coll.Indexes().CreateOne(connectCtx, mongo.IndexModel{
		Keys:    bson.D{{Key: "tenant_id", Value: 1}},
		Options: options.Index().SetUnique(true).SetName("tenant_id_unique"),
	}); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("create tenant index: %w", err)
	}
	return store, nil
}

func (s *Store) Close(ctx context.Context) error {
	return s.client.Disconnect(ctx)
}

// Get returns the tenant's record. A destroyed operator slot is reported as an
// empty (nil) wrap with its key still present.
func (s *Store) Get(tenantID string) (registry.CommitmentRecord, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	var d document
	if err := s.coll.FindOne(ctx, bson.M{"tenant_id": tenantID}).Decode(&d); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return registry.CommitmentRecord{}, false, nil
		}
		return registry.CommitmentRecord{}, false, err
	}

	record := registry.CommitmentRecord{
		TenantID:   d.TenantID,
		KeyVersion: d.KeyVersion,
		SeedCommit: d.SeedCommit,
		Wraps:      make(map[string][]byte, len(d.Wraps)),
		Callbacks:  d.Callbacks,
	}
	for op, encoded := range d.Wraps {
		if encoded == "" {
			record.Wraps[op] = nil
			continue
		}
		wrap, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return registry.CommitmentRecord{}, false, fmt.Errorf("decode wrap for %s: %w", op, err)
		}
		record.Wraps[op] = wrap
	}
	return record, true, nil
}

// Save writes a whole record (used by onboarding). Wraps given here are added to
// whatever the tenant already has, matching the demo registry.
func (s *Store) Save(record registry.CommitmentRecord) error {
	if strings.TrimSpace(record.TenantID) == "" {
		return fmt.Errorf("tenant_id is required")
	}
	for op, wrap := range record.Wraps {
		if err := s.PutWrap(record.TenantID, op, wrap, record.SeedCommit); err != nil {
			return err
		}
	}
	if record.KeyVersion == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	_, err := s.coll.UpdateOne(ctx,
		bson.M{"tenant_id": record.TenantID},
		bson.M{"$set": bson.M{"key_version": record.KeyVersion, "updated_at": time.Now().UTC()}},
	)
	return err
}

// PutWrap registers (or re-seals) one operator's key material. It refuses to mix
// seeds: if the tenant already commits to a different seed, the write is rejected.
func (s *Store) PutWrap(tenantID, operatorID string, wrap []byte, seedCommit string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(operatorID) == "" {
		return fmt.Errorf("tenant_id and operator_id are required")
	}
	if len(wrap) == 0 {
		return fmt.Errorf("wrap is required")
	}
	if err := validField(operatorID); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	set := bson.M{
		"wraps." + operatorID: base64.StdEncoding.EncodeToString(wrap),
		"updated_at":          time.Now().UTC(),
	}
	if strings.TrimSpace(seedCommit) != "" {
		set["seed_commit"] = seedCommit
	}

	// The filter accepts only a tenant that has no commitment yet or one that
	// matches. Upsert turns a mismatch into a duplicate-key error on tenant_id,
	// which is the conflict signal — one round trip, no read-modify-write race.
	filter := bson.M{
		"tenant_id": tenantID,
		"$or": bson.A{
			bson.M{"seed_commit": bson.M{"$exists": false}},
			bson.M{"seed_commit": ""},
			bson.M{"seed_commit": seedCommit},
		},
	}
	update := bson.M{
		"$set":         set,
		"$setOnInsert": bson.M{"tenant_id": tenantID, "destroyed_at": bson.M{}},
	}

	_, err := s.coll.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("%w for tenant %q", ErrSeedCommitConflict, tenantID)
		}
		return err
	}
	return nil
}

// PutCallback records how a coordinator can reach one operator node for this scope.
func (s *Store) PutCallback(tenantID, operatorID, callbackURL string) error {
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if err := validField(operatorID); err != nil {
		return err
	}
	if strings.TrimSpace(callbackURL) == "" {
		return fmt.Errorf("callback url is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	result, err := s.coll.UpdateOne(ctx,
		bson.M{"tenant_id": tenantID},
		bson.M{"$set": bson.M{
			"callbacks." + operatorID: callbackURL,
			"updated_at":              time.Now().UTC(),
		}},
	)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("record not found for tenant %q", tenantID)
	}
	return nil
}

// DestroyWrap zeroes one operator's material while keeping its slot, so the
// destruction quorum survives the erasure. Reports whether material was present.
func (s *Store) DestroyWrap(tenantID, operatorID string) (bool, error) {
	if err := validField(operatorID); err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	result, err := s.coll.UpdateOne(ctx,
		bson.M{
			"tenant_id":           tenantID,
			"wraps." + operatorID: bson.M{"$exists": true, "$ne": ""},
		},
		bson.M{"$set": bson.M{
			"wraps." + operatorID:        "",
			"destroyed_at." + operatorID: time.Now().UTC(),
			"updated_at":                 time.Now().UTC(),
		}},
	)
	if err != nil {
		return false, err
	}
	return result.ModifiedCount > 0, nil
}

// validField rejects operator ids that cannot be used as a document field path.
func validField(operatorID string) error {
	if strings.ContainsAny(operatorID, ".\x00") || strings.HasPrefix(operatorID, "$") {
		return fmt.Errorf("invalid operator_id %q", operatorID)
	}
	return nil
}
