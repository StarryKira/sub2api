package admin

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
)

// clandesConfigRequest is the payload for UpdateConfig.
// AuthToken is a pointer: nil means "keep existing", empty string means "clear".
type clandesConfigRequest struct {
	Enabled           bool    `json:"enabled"`
	Addr              string  `json:"addr" binding:"required"`
	AuthToken         *string `json:"auth_token"`
	ReconnectInterval int     `json:"reconnect_interval" binding:"min=1"`
}

// GetConfig returns the current clandes config from the loaded config file.
// auth_token is never returned; auth_token_configured flags whether it's set.
// GET /api/v1/admin/clandes/config
func (h *ClandesHandler) GetConfig(c *gin.Context) {
	response.Success(c, gin.H{
		"enabled":               viper.GetBool("clandes.enabled"),
		"addr":                  viper.GetString("clandes.addr"),
		"auth_token_configured": viper.GetString("clandes.auth_token") != "",
		"reconnect_interval":    viper.GetInt("clandes.reconnect_interval"),
		"config_file":           viper.ConfigFileUsed(),
	})
}

// UpdateConfig writes the clandes section to config.yaml and restarts the process.
// The caller must run sub2api under a supervisor (Docker restart policy / systemd)
// for the restart to produce a running server again.
// POST /api/v1/admin/clandes/config
func (h *ClandesHandler) UpdateConfig(c *gin.Context) {
	var req clandesConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, 400, err.Error())
		return
	}

	path := viper.ConfigFileUsed()
	if path == "" {
		response.Error(c, 500, "no config file is loaded; cannot persist clandes settings")
		return
	}

	// If AuthToken is nil, preserve the existing token from viper.
	authToken := viper.GetString("clandes.auth_token")
	if req.AuthToken != nil {
		authToken = *req.AuthToken
	}

	if err := updateClandesYAMLSection(path, req.Enabled, req.Addr, authToken, req.ReconnectInterval); err != nil {
		response.Error(c, 500, "failed to update config: "+err.Error())
		return
	}

	response.Success(c, gin.H{"message": "config saved; restarting process", "config_file": path})

	// Trigger graceful shutdown after response is flushed. Rely on external
	// supervisor (Docker / systemd) to restart the process.
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()
}

// updateClandesYAMLSection rewrites (or appends) the `clandes:` top-level section
// in the given YAML file, preserving comments and other sections via yaml.Node.
func updateClandesYAMLSection(path string, enabled bool, addr, authToken string, reconnectInterval int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}

	var top *yaml.Node
	switch {
	case root.Kind == yaml.DocumentNode && len(root.Content) > 0 && root.Content[0].Kind == yaml.MappingNode:
		top = root.Content[0]
	case len(data) == 0:
		// Empty file — build a fresh document.
		top = &yaml.Node{Kind: yaml.MappingNode}
		root = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{top}}
	default:
		return fmt.Errorf("unexpected yaml structure at root")
	}

	newValue := buildClandesMappingNode(enabled, addr, authToken, reconnectInterval)

	// Find existing clandes key under the top mapping; replace value in place.
	found := false
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "clandes" {
			top.Content[i+1] = newValue
			found = true
			break
		}
	}
	if !found {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "clandes", Tag: "!!str"}
		top.Content = append(top.Content, keyNode, newValue)
	}

	out, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func buildClandesMappingNode(enabled bool, addr, authToken string, reconnectInterval int) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode}
	add := func(k, v, tag string) {
		n.Content = append(n.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: k, Tag: "!!str"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: v, Tag: tag},
		)
	}
	add("enabled", fmt.Sprintf("%t", enabled), "!!bool")
	add("addr", addr, "!!str")
	add("auth_token", authToken, "!!str")
	add("reconnect_interval", fmt.Sprintf("%d", reconnectInterval), "!!int")
	return n
}
