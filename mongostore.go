// Copyright 2012 The KidStuff Authors.
// Copyright (c) 2022 Bos Hieu.
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mongostore

import (
	"context"
	"encoding/base32"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var ErrInvalidId = errors.New("mgostore: invalid session id")

// Session object store in MongoDB
type Session struct {
	Id       string `bson:"_id,omitempty"`
	Data     string
	Modified time.Time
}

// MongoStore stores sessions in MongoDB
type MongoStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	Token   TokenGetSeter
	coll    *mongo.Collection
}

var base32RawStdEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewMongoStore returns a new MongoStore.
// Set ensureTTL to true let the database auto-remove expired object by maxAge.
func NewMongoStore(c *mongo.Collection, maxAge int, ensureTTL bool,
	keyPairs ...[]byte,
) *MongoStore {
	store := &MongoStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: maxAge,
		},
		Token: &CookieToken{},
		coll:  c,
	}

	store.MaxAge(maxAge)

	if ensureTTL {
		background := true
		sparse := true
		expireAfter := int32(maxAge)
		_, err := c.Indexes().CreateOne(context.Background(), mongo.IndexModel{
			Keys: bson.M{"modified": 1},
			Options: &options.IndexOptions{
				Background:         &background,
				Sparse:             &sparse,
				ExpireAfterSeconds: &expireAfter,
			},
		})
		if err != nil {
			panic(err)
		}
	}

	return store
}

// Get registers and returns a session for the given name and session store.
// It returns a new session if there are no sessions registered for the name.
func (m *MongoStore) Get(r *http.Request, name string) (
	*sessions.Session, error,
) {
	return sessions.GetRegistry(r).Get(m, name)
}

// New returns a session for the given name without adding it to the registry.
func (m *MongoStore) New(r *http.Request, name string) (
	*sessions.Session, error,
) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:     m.Options.Path,
		MaxAge:   m.Options.MaxAge,
		Domain:   m.Options.Domain,
		Secure:   m.Options.Secure,
		HttpOnly: m.Options.HttpOnly,
		SameSite: m.Options.SameSite,
	}
	session.IsNew = true
	var err error
	cook, errToken := m.Token.GetToken(r, name)
	if errToken == nil {
		err = securecookie.DecodeMulti(name, cook, &session.ID, m.Codecs...)
		if err == nil {
			err = m.load(session)
			if err == nil {
				session.IsNew = false
			} else {
				err = nil
			}
		}
	}
	return session, err
}

// Save saves all sessions registered for the current request.
func (m *MongoStore) Save(_ *http.Request, w http.ResponseWriter,
	session *sessions.Session,
) error {
	if session.Options.MaxAge < 0 {
		if err := m.delete(session); err != nil {
			return err
		}
		m.Token.SetToken(w, session.Name(), "", session.Options)
		return nil
	}

	if session.ID == "" {
		session.ID = base32RawStdEncoding.EncodeToString(
			securecookie.GenerateRandomKey(32))
	}

	if err := m.upsert(session); err != nil {
		return err
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		m.Codecs...)
	if err != nil {
		return err
	}

	m.Token.SetToken(w, session.Name(), encoded, session.Options)
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (m *MongoStore) MaxAge(age int) {
	m.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range m.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new Store is 4096.
func (m *MongoStore) MaxLength(l int) {
	for _, c := range m.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

func (m *MongoStore) load(session *sessions.Session) error {
	s := Session{}
	err := m.coll.FindOne(context.TODO(), makeFilterByID(session.ID)).Decode(&s)
	if err != nil {
		return err
	}

	return securecookie.DecodeMulti(session.Name(), s.Data, &session.Values, m.Codecs...)
}

func (m *MongoStore) upsert(session *sessions.Session) error {
	var modified time.Time
	if val, ok := session.Values["modified"]; ok {
		modified, ok = val.(time.Time)
		if !ok {
			return errors.New("mongostore: invalid modified value")
		}
	} else {
		modified = time.Now()
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		m.Codecs...)
	if err != nil {
		return err
	}

	s := Session{
		Id:       session.ID,
		Data:     encoded,
		Modified: modified,
	}

	updateOption := options.Update().SetUpsert(true)
	updateData := bson.M{"$set": s}
	_, err = m.coll.UpdateByID(context.TODO(), s.Id, updateData, updateOption)
	if err != nil {
		return err
	}

	return nil
}

func (m *MongoStore) delete(session *sessions.Session) error {
	_, err := m.coll.DeleteOne(context.TODO(), makeFilterByID(session.ID))
	if err != nil {
		return err
	}

	return nil
}

func makeFilterByID(sessionID string) bson.D {
	return bson.D{{Key: "_id", Value: sessionID}}
}
