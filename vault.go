package viper

import (
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault-client-go"
)

// Pair of key and value
type KVEntry struct {
	Key   string
	Value string
}

// Configuration for watching for vault's secrets.
// Version period - how often to check for changes in secrets (0 if never)
// AlertChannel - channel to send changes to
type VaultWatchConfig struct {
	VersionPeriod time.Duration
	AlertChannel  chan<- KVEntry
}

type vaultClient struct {
	client      *vault.Client
	vaults      map[string]string
	leases      map[string]int
	versions    map[string]int
	watchConfig *VaultWatchConfig
}

func isVersionable(vtype string) bool {
	return vtype == "kv"
}

func isLeasable(vtype string) bool {
	return vtype == "database"
}

func (c *vaultClient) ConfigureVault() error {
	vaults, err := c.client.System.InternalUiListEnabledVisibleMounts(context.Background())

	if err != nil {
		return err
	}
	c.vaults = make(map[string]string, len(vaults.Data.Secret))
	for vault, data := range vaults.Data.Secret {
		if strings.HasPrefix(vault, "sys/") || vault == "cubbyhole/" || vault == "identity/" {
			continue
		}
		dataMap := data.(map[string]any)
		c.vaults[vault] = dataMap["type"].(string)
	}
	return nil
}

func (c *vaultClient) getKV2(mountPath string, key string, secretName string) ([]byte, int, error) {
	data, err := c.client.Secrets.KvV2Read(context.Background(), key, vault.WithMountPath(mountPath))
	if err != nil {
		return nil, 0, err
	}
	secret, ok := data.Data.Data[secretName].(string)

	if !ok {
		return nil, 0, fmt.Errorf("Secret ( %s ) does not exist.", secretName)
	}
	version, err := data.Data.Metadata["version"].(json.Number).Int64()
	if err != nil {
		return nil, 0, err
	}
	return []byte(secret), int(version), nil
}

func (c *vaultClient) getDBCreds(mountPath string, role string) ([]byte, int, error) {
	data, err := c.client.Secrets.DatabaseGenerateCredentials(context.Background(), role, vault.WithMountPath(mountPath))
	if err != nil {
		return nil, 0, err
	}
	username := data.Data["username"].(string)
	password := data.Data["password"].(string)
	lifetime := data.LeaseDuration
	return []byte(username + ":" + password), lifetime, nil
}

func (c *vaultClient) getVaultTypePath(key string) (string, string, error) {
	var vaultType, mountPath string
	for vault, vtype := range c.vaults {
		if strings.HasPrefix(key, vault) {
			vaultType = vtype
			mountPath = vault[:len(vault)-1]
			return vaultType, mountPath, nil
		}
	}
	return "", "", fmt.Errorf("Secrets engine for key ( %s ) does not exist.", key)
}

func (c *vaultClient) get(key string) ([]byte, int, error) {
	vaultType, mountPath, err := c.getVaultTypePath(key)
	key = strings.TrimPrefix(key, mountPath+"/")
	if err != nil {
		return nil, 0, err
	}
	switch vaultType {
	case "kv":
		keyWithName := strings.Split(key, ":")
		resp, version, err := c.getKV2(mountPath, keyWithName[0], keyWithName[1])
		if err != nil {
			return nil, 0, err
		}
		if c.watchConfig != nil && c.watchConfig.VersionPeriod != 0 {
			c.versions[mountPath+"/"+key] = version
		}
		return resp, version, nil
	case "database":
		resp, leaseTime, err := c.getDBCreds(mountPath, key)
		if err != nil {
			return nil, 0, err
		}
		if c.watchConfig != nil {
			c.leases[mountPath+"/"+key] = leaseTime
		}
		return resp, leaseTime, nil
	}
	return nil, 0, fmt.Errorf("Vault type ( %s ) is not supported.", vaultType)
}

func (c *vaultClient) Get(key string) ([]byte, error) {
	bts, _, err := c.get(key)
	return bts, err
}

type Watchable struct {
	path    string
	nextGet time.Time
}

type watchableHeap []Watchable

func (h watchableHeap) Len() int {
	return len(h)
}

func (h watchableHeap) Less(i, j int) bool {
	return h[i].nextGet.Unix() < h[j].nextGet.Unix()
}

func (h watchableHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *watchableHeap) Push(val any) {
	*h = append(*h, val.(Watchable))
}

func (h *watchableHeap) Pop() any {
	heapDerefrenced := *h

	size := len(heapDerefrenced)
	val := heapDerefrenced[size-1]
	*h = heapDerefrenced[:size-1]

	return val
}

func (v *Viper) watchVault(c *vaultClient) {
	h := watchableHeap{}
	for path, leaseTime := range c.leases {
		heap.Push(&h, Watchable{path: path, nextGet: time.Now().Add(time.Duration(leaseTime) * time.Second)})
	}
	if c.watchConfig.VersionPeriod != 0 {
		for path, _ := range c.versions {
			heap.Push(&h, Watchable{path: path, nextGet: time.Now().Add(c.watchConfig.VersionPeriod)})
		}
	}
	if len(h) == 0 {
		v.logger.Error("No watchable paths found for vault watching.")
		close(c.watchConfig.AlertChannel)
		return
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if len(h) == 0 {
				time.Sleep(time.Duration(1) * time.Second)
				continue
			}
			event := heap.Pop(&h).(Watchable)
			eventVaultType := c.vaults[strings.Split(event.path, "/")[0]+"/"]
			time.Sleep(time.Until(event.nextGet))
			if c.watchConfig.VersionPeriod != 0 && isVersionable(eventVaultType) {
				oldVersion := c.versions[event.path]
				data, version, err := c.get(event.path)
				if err != nil {
					v.logger.Error("Error watching versionable vault secret on path", event.path, err.Error())
					return
				}
				if version > oldVersion {
					v.secretstore[event.path] = string(data)
					c.watchConfig.AlertChannel <- KVEntry{Key: event.path, Value: string(data)}
				}
				heap.Push(&h, Watchable{path: event.path, nextGet: time.Now().Add(c.watchConfig.VersionPeriod)})
			} else if isLeasable(eventVaultType) {
				data, leaseTime, err := c.get(event.path)
				if err != nil {
					v.logger.Error("Error watching leasable vault secret on path", event.path, err.Error())
					return
				}
				v.secretstore[event.path] = string(data)
				c.watchConfig.AlertChannel <- KVEntry{Key: event.path, Value: string(data)}
				heap.Push(&h, Watchable{path: event.path, nextGet: time.Now().Add(time.Duration(leaseTime) * time.Second)})
			}
		}
	}()
	wg.Wait()
}

// AddVault adds a vault to the viper.
// Client should be authorized with token set.
// WatchConfig shoul be nil if you don't have dynamic secrets
func (v *Viper) AddVault(client *vault.Client, watchConfig *VaultWatchConfig, paths ...string) error {
	c := &vaultClient{client: client, watchConfig: nil}

	err := c.ConfigureVault()

	if err != nil {
		return err
	}

	if watchConfig != nil {
		c.watchConfig = watchConfig
		c.leases = make(map[string]int)
		if watchConfig.VersionPeriod != 0 {
			c.versions = make(map[string]int)
		}
	}

	for _, path := range paths {
		data, err := c.Get(path)
		if err != nil {
			return fmt.Errorf("Error while adding vault: %s, path: %s", err, path)
		}
		v.secretstore[path] = string(data)
	}

	if watchConfig != nil {
		go func() {
			v.watchVault(c)
		}()
	}
	return nil
}
