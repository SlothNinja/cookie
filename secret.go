package cookie

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/SlothNinja/client"
	"github.com/SlothNinja/log"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gorilla/securecookie"
)

const (
	msgEnter         = "Entering"
	msgExit          = "Exiting"
	hashKeyLength    = 64
	blockKeyLength   = 32
	secretsProjectID = "SECRETS_PROJECT_ID"
	secretsDSHost    = "SECRETS_DS_HOST"
)

// secret stores secrets for secure cookie
type secret struct {
	HashKey   []byte         `json:"hashKey"`
	BlockKey  []byte         `json:"blockKey"`
	UpdatedAt time.Time      `json:"updatedAt"`
	Key       *datastore.Key `datastore:"__key__" json:"-"`
}

// Client for generating secure cookie store
type Client struct {
	*client.Client
}

// NewClient creates a client for generating a secured cookie store
func NewClient(snClient *client.Client) *Client {
	return &Client{snClient}
}

func (cl *Client) get(c context.Context) (*secret, error) {
	cl.Log.Debugf(msgEnter)
	defer cl.Log.Debugf(msgExit)

	s, found := cl.mcGet()
	if found {
		return s, nil
	}

	s, err := cl.dsGet(c)
	if err != datastore.ErrNoSuchEntity {
		return s, err
	}

	cl.Log.Warningf("generated new secrets")
	return cl.update(c)
}

// mcGet attempts to pull secret from cache
func (cl *Client) mcGet() (*secret, bool) {
	cl.Log.Debugf(msgEnter)
	defer cl.Log.Debugf(msgExit)

	k := key().Encode()

	item, found := cl.Cache.Get(k)
	if !found {
		return nil, false
	}

	s, ok := item.(*secret)
	if !ok {
		cl.Cache.Delete(k)
		return nil, false
	}
	return s, true
}

// dsGet attempt to pull secret from datastore
func (cl *Client) dsGet(c context.Context) (*secret, error) {
	cl.Log.Debugf(msgEnter)
	defer cl.Log.Debugf(msgExit)

	s := &secret{Key: key()}
	err := cl.DS.Get(c, s.Key, s)
	return s, err
}

func (cl *Client) update(c context.Context) (*secret, error) {
	s, err := genSecret()
	if err != nil {
		return nil, err
	}

	_, err = cl.DS.Put(c, s.Key, s)
	return s, err
}

func key() *datastore.Key {
	return datastore.NameKey("Secrets", "cookie", nil)
}

func genSecret() (*secret, error) {
	s := &secret{
		HashKey:  securecookie.GenerateRandomKey(hashKeyLength),
		BlockKey: securecookie.GenerateRandomKey(blockKeyLength),
		Key:      key(),
	}

	if s.HashKey == nil {
		return s, fmt.Errorf("generated hashKey was nil")
	}

	if s.BlockKey == nil {
		return s, fmt.Errorf("generated blockKey was nil")
	}

	return s, nil
}

func (s *secret) Load(ps []datastore.Property) error {
	return datastore.LoadStruct(s, ps)
}

func (s *secret) Save() ([]datastore.Property, error) {
	s.UpdatedAt = time.Now()
	return datastore.SaveStruct(s)
}

func (s *secret) LoadKey(k *datastore.Key) error {
	s.Key = k
	return nil
}

// Store represents a secure cookie store
type Store cookie.Store

// NewStore generates a new secure cookie store
func (cl *Client) NewStore(ctx context.Context) (Store, error) {
	log.Debugf(msgEnter)
	defer log.Debugf(msgExit)

	s, err := cl.get(ctx)
	if err != nil {
		return nil, err
	}

	if !client.IsProduction() {
		cl.Log.Debugf("hashKey: %s\nblockKey: %s",
			base64.StdEncoding.EncodeToString(s.HashKey),
			base64.StdEncoding.EncodeToString(s.BlockKey),
		)
		store := cookie.NewStore(s.HashKey, s.BlockKey)
		opts := sessions.Options{
			Domain: "fake-slothninja.com",
			Path:   "/",
		}
		store.Options(opts)
		return store, nil
	}
	store := cookie.NewStore(s.HashKey, s.BlockKey)
	opts := sessions.Options{
		Domain: "slothninja.com",
		Path:   "/",
		Secure: true,
	}
	store.Options(opts)
	return store, nil
}
