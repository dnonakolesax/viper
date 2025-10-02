package viper

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

func TestVault(t *testing.T) {
	v = New()
	address := "http://192.168.80.3:8200"
	login := "dunkelheit"
	password := "dunkelheit"
	vClient, err := vault.New(vault.WithAddress(address))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	resp, err := vClient.Auth.UserpassLogin(context.Background(), login, schema.UserpassLoginRequest{
		Password: password,
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	err = vClient.SetToken(resp.Auth.ClientToken)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	err = v.AddVault(vClient, nil, "sample/secret:sample")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if val := v.Get("sample/secret:sample"); val != "text" {
		t.Error(fmt.Errorf("sample-value is %s, expected: text", val))
		t.FailNow()
	}
}

func TestVaultListen(t *testing.T) {
	address := "http://192.168.80.3:8200"
	login := "dunkelheit"
	password := "dunkelheit"
	vClient, err := vault.New(vault.WithAddress(address))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	resp, err := vClient.Auth.UserpassLogin(context.Background(), login, schema.UserpassLoginRequest{
		Password: password,
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	err = vClient.SetToken(resp.Auth.ClientToken)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	eventChan := make(chan KVEntry)

	vaultWatchConf := VaultWatchConfig{
		VersionPeriod: time.Second * 0,
		AlertChannel:  eventChan,
	}

	err = v.AddVault(vClient, &vaultWatchConf, "sample/secret:sample")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if val := v.Get("sample/secret:sample"); val != "text" {
		t.Error(fmt.Errorf("sample-value is %s, expected: text", val))
		t.FailNow()
	}

	event := <-eventChan
	fmt.Printf("%s %s\n", event.Key, event.Value)
}
