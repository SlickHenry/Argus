package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config structures
type Config struct {
	OAuth2          OAuth2Config                     `json:"oauth2"`
	Organizations   OrganizationConfig               `json:"organizations"`
	Syslog          SyslogConfig                     `json:"syslog"`
	API             APIConfig                        `json:"api"`
	FieldMappings   map[string]map[string]string     `json:"field_mappings"`
	PollingInterval int                              `json:"polling_interval_seconds"`
}

type OAuth2Config struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TokenURL     string `json:"token_url"`
	Scope        string `json:"scope"`
}

type OrganizationConfig struct {
	Mode            string   `json:"mode"`              // "all", "include", "exclude"
	OrganizationIDs []string `json:"organization_ids"`  // List of org IDs to include/exclude
	DefaultOrgID    string   `json:"default_org_id"`    // Default org if none specified
}

type SyslogConfig struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type APIConfig struct {
	BaseURL   string   `json:"base_url"`
	Endpoints []string `json:"endpoints"`
}

// State management - track last timestamps per org/endpoint
type State struct {
	LastPolledTimes map[string]time.Time `json:"last_polled_times"` // key: "orgID-endpoint"
	AccessToken     string               `json:"access_token,omitempty"`
	TokenExpiry     time.Time            `json:"token_expiry,omitempty"`
	FirstRun        bool                 `json:"first_run,omitempty"` // Track if this is first run
}

// OAuth2 token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// Organization API response
type OrganizationResponse struct {
	IDRaw           interface{} `json:"id"`
	Name            string      `json:"name"`
	Description     string      `json:"description,omitempty"`
	NodeApprovalMode string     `json:"nodeApprovalMode,omitempty"`
}

// Helper method to get ID as string regardless of JSON type
func (o *OrganizationResponse) GetID() string {
	switch v := o.IDRaw.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// API response structures
type APIResponse struct {
	Data []map[string]interface{} `json:"data,omitempty"`
}

// API client
type APIClient struct {
	config         *Config
	accessToken    string
	tokenExpiry    time.Time
	httpClient     *http.Client
	stateManager   *StateManager
	organizations  []OrganizationResponse
}

// CEF formatter
type CEFFormatter struct {
	vendor        string
	product       string
	version       string
	fieldMappings map[string]map[string]string
}

// Syslog client
type SyslogClient struct {
	config *SyslogConfig
	conn   net.Conn
}

// State manager
type StateManager struct {
	filePath string
	state    *State
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		printUsage()
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "--list-orgs" {
		listOrganizations()
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "--reset-state" {
		resetState()
		return
	}

	configFile := "config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	// Load configuration
	config, err := loadConfig(configFile)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialize components
	stateManager := NewStateManager("state.json")
	apiClient := NewAPIClient(config, stateManager)
	cefFormatter := NewCEFFormatter("NinjaRMM", "RMM", "1.0", config.FieldMappings)
	syslogClient := NewSyslogClient(&config.Syslog)

	// Load previous state
	isFirstRun := false
	if err := stateManager.Load(); err != nil {
		fmt.Printf("No previous state found - performing initial comprehensive collection\n")
		stateManager.state.LastPolledTimes = make(map[string]time.Time)
		stateManager.state.FirstRun = true
		isFirstRun = true
	} else {
		isFirstRun = stateManager.state.FirstRun
		if isFirstRun {
			fmt.Printf("Continuing initial comprehensive collection\n")
		} else {
			fmt.Printf("Resuming incremental polling from previous state\n")
		}
	}

	// Load and filter organizations
	if err := apiClient.loadOrganizations(); err != nil {
		fmt.Printf("Error loading organizations: %v\n", err)
		os.Exit(1)
	}

	// Connect to syslog
	if err := syslogClient.Connect(); err != nil {
		fmt.Printf("Error connecting to syslog: %v\n", err)
		os.Exit(1)
	}
	defer syslogClient.Close()

	// Main polling loop
	ticker := time.NewTicker(time.Duration(config.PollingInterval) * time.Second)
	defer ticker.Stop()

	if isFirstRun {
		fmt.Printf("Starting NinjaRMM API client (INITIAL COLLECTION) - gathering all available logs for %d organizations...\n", 
			len(apiClient.organizations))
	} else {
		fmt.Printf("Starting NinjaRMM API client (INCREMENTAL) - polling %d organizations every %d seconds...\n", 
			len(apiClient.organizations), config.PollingInterval)
	}

	// Initial poll
	pollAndForward(apiClient, cefFormatter, syslogClient, stateManager, config)

	for range ticker.C {
		pollAndForward(apiClient, cefFormatter, syslogClient, stateManager, config)
	}
}

func printUsage() {
	fmt.Println("NinjaRMM API to Syslog Forwarder")
	fmt.Println("Usage: ninja-api-client [config-file]")
	fmt.Println("       ninja-api-client --list-orgs")
	fmt.Println("       ninja-api-client --reset-state")
	fmt.Println("       ninja-api-client --help")
	fmt.Println("")
	fmt.Println("  config-file: Path to JSON configuration file (default: config.json)")
	fmt.Println("  --list-orgs: List all available organizations")
	fmt.Println("  --reset-state: Reset polling timestamps (start fresh comprehensive collection)")
	fmt.Println("")
	fmt.Println("Organization Filtering:")
	fmt.Println("  mode: 'all' - Query all organizations")
	fmt.Println("  mode: 'include' - Only query specified organization_ids")
	fmt.Println("  mode: 'exclude' - Query all except specified organization_ids")
	fmt.Println("")
	fmt.Println("Collection Modes:")
	fmt.Println("  First run: Comprehensive collection of all available logs")
	fmt.Println("  Subsequent runs: Incremental collection using timestamps")
}

func listOrganizations() {
	fmt.Println("Loading organizations...")
	
	config, err := loadConfig("config.json")
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		return
	}

	stateManager := NewStateManager("state.json")
	apiClient := NewAPIClient(config, stateManager)

	if err := apiClient.loadAllOrganizations(); err != nil {
		fmt.Printf("Error loading organizations: %v\n", err)
		return
	}

	fmt.Printf("\nAvailable Organizations (%d total):\n", len(apiClient.organizations))
	fmt.Println("ID\t\t\t\t\tName")
	fmt.Println("--------------------------------------------------------------------")
	for _, org := range apiClient.organizations {
		fmt.Printf("%s\t%s\n", org.GetID(), org.Name)
	}
}

func resetState() {
	fmt.Println("Resetting polling state...")
	stateManager := NewStateManager("state.json")
	stateManager.state = &State{
		LastPolledTimes: make(map[string]time.Time),
		FirstRun:        true,
	}
	if err := stateManager.Save(); err != nil {
		fmt.Printf("Error resetting state: %v\n", err)
		return
	}
	fmt.Println("State reset successfully. Next run will perform comprehensive collection of all available logs.")
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Set defaults
	if config.OAuth2.TokenURL == "" {
		config.OAuth2.TokenURL = "https://app.ninjarmm.com/oauth/token"
	}
	if config.Organizations.Mode == "" {
		config.Organizations.Mode = "all"
	}

	// Validate required fields
	if config.OAuth2.ClientID == "" {
		return nil, fmt.Errorf("OAuth2 client_id is required")
	}
	if config.OAuth2.ClientSecret == "" {
		return nil, fmt.Errorf("OAuth2 client_secret is required")
	}
	if config.Syslog.Server == "" {
		return nil, fmt.Errorf("Syslog server is required")
	}
	if config.API.BaseURL == "" {
		return nil, fmt.Errorf("API base_url is required")
	}

	return &config, nil
}

func NewAPIClient(config *Config, stateManager *StateManager) *APIClient {
	return &APIClient{
		config:       config,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		stateManager: stateManager,
	}
}

func NewCEFFormatter(vendor, product, version string, fieldMappings map[string]map[string]string) *CEFFormatter {
	return &CEFFormatter{
		vendor:        vendor,
		product:       product,
		version:       version,
		fieldMappings: fieldMappings,
	}
}

func NewSyslogClient(config *SyslogConfig) *SyslogClient {
	return &SyslogClient{
		config: config,
	}
}

func NewStateManager(filePath string) *StateManager {
	return &StateManager{
		filePath: filePath,
		state: &State{
			LastPolledTimes: make(map[string]time.Time),
			FirstRun:        true,
		},
	}
}

// Organization loading and filtering
func (c *APIClient) loadOrganizations() error {
	if err := c.loadAllOrganizations(); err != nil {
		return err
	}

	filteredOrgs := c.filterOrganizations()
	c.organizations = filteredOrgs

	fmt.Printf("Loaded %d organizations for monitoring\n", len(c.organizations))
	for _, org := range c.organizations {
		fmt.Printf("  - %s (%s)\n", org.Name, org.GetID())
	}

	return nil
}

func (c *APIClient) loadAllOrganizations() error {
	if err := c.getAccessToken(); err != nil {
		return fmt.Errorf("failed to get access token: %v", err)
	}

	req, err := http.NewRequest("GET", c.config.API.BaseURL+"/organizations", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NinjaRMM-API-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("organizations request failed: %d - %s", resp.StatusCode, string(body))
	}

	var organizations []OrganizationResponse
	if err := json.Unmarshal(body, &organizations); err != nil {
		return fmt.Errorf("failed to parse organizations response: %v", err)
	}

	c.organizations = organizations
	return nil
}

func (c *APIClient) filterOrganizations() []OrganizationResponse {
	switch c.config.Organizations.Mode {
	case "all":
		return c.organizations
	case "include":
		return c.filterIncludeOrganizations()
	case "exclude":
		return c.filterExcludeOrganizations()
	default:
		fmt.Printf("Warning: unknown organization mode '%s', using 'all'\n", c.config.Organizations.Mode)
		return c.organizations
	}
}

func (c *APIClient) filterIncludeOrganizations() []OrganizationResponse {
	if len(c.config.Organizations.OrganizationIDs) == 0 {
		return c.organizations
	}

	var filtered []OrganizationResponse
	for _, org := range c.organizations {
		for _, id := range c.config.Organizations.OrganizationIDs {
			if org.GetID() == id {
				filtered = append(filtered, org)
				break
			}
		}
	}
	return filtered
}

func (c *APIClient) filterExcludeOrganizations() []OrganizationResponse {
	if len(c.config.Organizations.OrganizationIDs) == 0 {
		return c.organizations
	}

	var filtered []OrganizationResponse
	for _, org := range c.organizations {
		excluded := false
		for _, id := range c.config.Organizations.OrganizationIDs {
			if org.GetID() == id {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, org)
		}
	}
	return filtered
}

// OAuth2 token management (Client Credentials only)
func (c *APIClient) getAccessToken() error {
	if time.Now().Before(c.tokenExpiry) && c.accessToken != "" {
		return nil
	}

	fmt.Println("Acquiring new OAuth2 token...")

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.config.OAuth2.ClientID)
	data.Set("client_secret", c.config.OAuth2.ClientSecret)
	
	if c.config.OAuth2.Scope != "" {
		data.Set("scope", c.config.OAuth2.Scope)
	}

	req, err := http.NewRequest("POST", c.config.OAuth2.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NinjaRMM-API-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request failed: %d - %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %v", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	// Store token in state for persistence
	c.stateManager.state.AccessToken = c.accessToken
	c.stateManager.state.TokenExpiry = c.tokenExpiry

	fmt.Printf("OAuth2 token acquired successfully (expires in %d seconds)\n", tokenResp.ExpiresIn)
	return nil
}

// API data fetching with device filter for organization targeting
func (c *APIClient) fetchActivities(orgID string, newerThan time.Time) ([]map[string]interface{}, error) {
	if err := c.getAccessToken(); err != nil {
		return nil, fmt.Errorf("failed to get access token: %v", err)
	}

	apiURL := c.config.API.BaseURL + "/activities"
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	
	// Add device filter for organization targeting
	// Format: df=org = {orgId} (URL encoded as df=org%20%3D%20{orgId})
	deviceFilter := fmt.Sprintf("org = %s", orgID)
	q.Set("df", deviceFilter)
	fmt.Printf("Adding device filter for org %s: %s\n", orgID, deviceFilter)
	
	// Only add timestamp filter if we have a valid timestamp (not first run)
	if !newerThan.IsZero() {
		unixTimestamp := newerThan.Unix()
		q.Set("since", fmt.Sprintf("%d", unixTimestamp))
		fmt.Printf("Adding since parameter: %d (%s)\n", unixTimestamp, newerThan.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("No timestamp filter applied (comprehensive collection)\n")
	}
	
	u.RawQuery = q.Encode()
	apiURL = u.String()

	fmt.Printf("Final activities URL: %s\n", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NinjaRMM-API-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed: %d - %s", resp.StatusCode, string(body))
	}

	// Parse the NinjaOne activities response structure
	var activitiesResp struct {
		LastActivityId int                      `json:"lastActivityId"`
		Activities     []map[string]interface{} `json:"activities"`
	}
	
	if err := json.Unmarshal(body, &activitiesResp); err != nil {
		return nil, fmt.Errorf("failed to parse activities response: %v", err)
	}

	result := activitiesResp.Activities
	fmt.Printf("Received %d activities for organization %s\n", len(result), orgID)

	// Add organizationId to each activity record for consistency
	for _, activity := range result {
		activity["organizationId"] = orgID
	}

	return result, nil
}

func (c *APIClient) fetchAlerts(orgID string, newerThan time.Time) ([]map[string]interface{}, error) {
	if err := c.getAccessToken(); err != nil {
		return nil, fmt.Errorf("failed to get access token: %v", err)
	}

	apiURL := c.config.API.BaseURL + "/alerts"
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	
	// Try adding device filter for organization targeting on alerts too
	// This might not work for alerts, but let's try
	deviceFilter := fmt.Sprintf("org = %s", orgID)
	q.Set("df", deviceFilter)
	fmt.Printf("Adding device filter for alerts org %s: %s\n", orgID, deviceFilter)
	
	// Only add timestamp filter if we have a valid timestamp (not first run)
	if !newerThan.IsZero() {
		unixTimestamp := newerThan.Unix()
		q.Set("since", fmt.Sprintf("%d", unixTimestamp))
		fmt.Printf("Adding since parameter: %d (%s)\n", unixTimestamp, newerThan.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("No timestamp filter applied (comprehensive collection)\n")
	}
	
	u.RawQuery = q.Encode()
	apiURL = u.String()

	fmt.Printf("Final alerts URL: %s\n", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NinjaRMM-API-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed: %d - %s", resp.StatusCode, string(body))
	}

	var result []map[string]interface{}
	
	// Try parsing as direct array first (alerts structure might be different)
	if err := json.Unmarshal(body, &result); err != nil {
		// Try object with data field
		var apiResp APIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			// Try alerts-specific structure (if it exists)
			var alertsResp struct {
				Alerts []map[string]interface{} `json:"alerts"`
			}
			if err := json.Unmarshal(body, &alertsResp); err != nil {
				return nil, fmt.Errorf("failed to parse alerts response: %v", err)
			}
			result = alertsResp.Alerts
		} else {
			result = apiResp.Data
		}
	}

	fmt.Printf("Received %d alerts for organization %s\n", len(result), orgID)

	// Add organizationId to each alert record for consistency
	for _, alert := range result {
		// Only add if not already present
		if extractStringField(alert, "organizationId", "") == "" {
			alert["organizationId"] = orgID
		}
	}

	return result, nil
}

// CEF formatting
func (f *CEFFormatter) formatToCEF(data map[string]interface{}, eventClassID, name string, severity int, endpoint string) string {
	cefHeader := fmt.Sprintf("CEF:0|%s|%s|%s|%s|info|%d|",
		f.vendor,
		f.product,
		f.version,
		f.escapeCEFValue(eventClassID),
		severity,
	)

	var extensions []string
	
	var mappings map[string]string
	if endpointMappings, exists := f.fieldMappings[endpoint]; exists {
		mappings = endpointMappings
	} else if defaultMappings, exists := f.fieldMappings["default"]; exists {
		mappings = defaultMappings
	} else {
		mappings = make(map[string]string)
	}
	
	processedFields := make(map[string]bool)
	for apiField, cefField := range mappings {
		if strings.HasPrefix(apiField, "_comment") {
			continue
		}
		if value, exists := data[apiField]; exists {
			cleanValue := f.cleanValue(value)
			extensions = append(extensions, fmt.Sprintf("%s=%s", cefField, f.escapeCEFValue(cleanValue)))
			processedFields[apiField] = true
		}
	}

	fieldCounter := 1
	for key, value := range data {
		if !processedFields[key] {
			if value == nil {
				continue
			}
			
			cleanValue := f.cleanValue(value)
			
			if len(cleanValue) > 0 && fieldCounter <= 2 {
				extensions = append(extensions, fmt.Sprintf("flexString%d=%s", fieldCounter, f.escapeCEFValue(cleanValue)))
				extensions = append(extensions, fmt.Sprintf("flexString%dLabel=%s", fieldCounter, f.escapeCEFValue(key)))
				fieldCounter++
			}
		}
	}

	return cefHeader + strings.Join(extensions, " ")
}

func (f *CEFFormatter) cleanValue(value interface{}) string {
	var valueStr string
	switch v := value.(type) {
	case map[string]interface{}, []interface{}:
		if jsonBytes, err := json.Marshal(v); err == nil {
			valueStr = string(jsonBytes)
		} else {
			valueStr = fmt.Sprintf("%v", v)
		}
	default:
		valueStr = fmt.Sprintf("%v", v)
	}
	
	valueStr = strings.ReplaceAll(valueStr, "\n", " ")
	valueStr = strings.ReplaceAll(valueStr, "\r", " ")
	valueStr = strings.ReplaceAll(valueStr, "\t", " ")
	valueStr = strings.TrimSpace(valueStr)
	
	if len(valueStr) > 500 {
		valueStr = valueStr[:497] + "..."
	}
	
	return valueStr
}

func (f *CEFFormatter) escapeCEFValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|") 
	value = strings.ReplaceAll(value, "=", "\\=")
	return value
}

// Syslog client methods
func (s *SyslogClient) Connect() error {
	address := fmt.Sprintf("%s:%d", s.config.Server, s.config.Port)
	
	fmt.Printf("Connecting to syslog server: %s (%s)\n", address, s.config.Protocol)
	
	var err error
	s.conn, err = net.Dial(s.config.Protocol, address)
	if err != nil {
		return err
	}
	
	fmt.Println("Successfully connected to syslog server")
	return nil
}

func (s *SyslogClient) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *SyslogClient) SendMessage(message string) error {
	if s.conn == nil {
		return fmt.Errorf("not connected to syslog server")
	}

	priority := 134
	timestamp := time.Now().Format("Jan _2 15:04:05")
	hostname, _ := os.Hostname()
	
	syslogMessage := fmt.Sprintf("<%d>%s %s NinjaRMM: %s\n", 
		priority, timestamp, hostname, message)

	_, err := s.conn.Write([]byte(syslogMessage))
	return err
}

// Enhanced state management with first-run logic
func (sm *StateManager) Load() error {
	data, err := os.ReadFile(sm.filePath)
	if err != nil {
		return err
	}
	
	if err := json.Unmarshal(data, sm.state); err != nil {
		return err
	}
	
	// Initialize map if nil
	if sm.state.LastPolledTimes == nil {
		sm.state.LastPolledTimes = make(map[string]time.Time)
	}
	
	return nil
}

func (sm *StateManager) Save() error {
	data, err := json.MarshalIndent(sm.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(sm.filePath, data, 0644)
}

func (sm *StateManager) GetLastPolledTime(key string) time.Time {
	if sm.state.LastPolledTimes == nil {
		return time.Time{} // Return zero time for first run
	}
	
	if lastTime, exists := sm.state.LastPolledTimes[key]; exists {
		return lastTime
	}
	
	return time.Time{} // Return zero time for first run of this endpoint
}

func (sm *StateManager) UpdateLastPolledTime(key string, t time.Time) {
	if sm.state.LastPolledTimes == nil {
		sm.state.LastPolledTimes = make(map[string]time.Time)
	}
	sm.state.LastPolledTimes[key] = t
}

func (sm *StateManager) MarkFirstRunComplete() {
	sm.state.FirstRun = false
}

// Main polling function with device filter support
func pollAndForward(apiClient *APIClient, cefFormatter *CEFFormatter, syslogClient *SyslogClient, stateManager *StateManager, config *Config) {
	fmt.Printf("Polling at %s\n", time.Now().Format("2006-01-02 15:04:05"))

	totalRecords := 0
	isFirstRun := stateManager.state.FirstRun

	// Poll each organization
	for _, org := range apiClient.organizations {
		orgID := org.GetID()
		fmt.Printf("Polling organization: %s (%s)\n", org.Name, orgID)
		
		// Poll each endpoint for this organization
		for _, endpoint := range config.API.Endpoints {
			endpointKey := fmt.Sprintf("%s-%s", orgID, endpoint)
			lastPolledTime := stateManager.GetLastPolledTime(endpointKey)
			
			if isFirstRun || lastPolledTime.IsZero() {
				fmt.Printf("  Fetching ALL available data from %s (comprehensive collection)\n", endpoint)
			} else {
				fmt.Printf("  Fetching data from %s (newer than %s)\n", endpoint, lastPolledTime.Format("2006-01-02 15:04:05"))
			}
			
			var data []map[string]interface{}
			var err error
			var latestTimestamp time.Time
			
			// Use appropriate fetch method based on endpoint
			switch endpoint {
			case "/activities":
				data, err = apiClient.fetchActivities(orgID, lastPolledTime)
			case "/alerts":
				data, err = apiClient.fetchAlerts(orgID, lastPolledTime)
			default:
				fmt.Printf("  Warning: Unknown endpoint %s, skipping\n", endpoint)
				continue
			}
			
			if err != nil {
				fmt.Printf("  Error fetching data from %s for org %s: %v\n", endpoint, orgID, err)
				continue
			}

			fmt.Printf("  Received %d records from %s\n", len(data), endpoint)
			totalRecords += len(data)

			for _, record := range data {
				// Add organization context to the record (if not already present)
				if extractStringField(record, "organizationId", "") == "" {
					record["organizationId"] = orgID
				}
				record["organizationName"] = org.Name
				
				eventClassID := extractStringField(record, "type", fmt.Sprintf("NINJA_%s", strings.ToUpper(strings.TrimPrefix(endpoint, "/"))))
				severity := mapSeverity(extractStringField(record, "severity", "INFO"))

				cefMessage := cefFormatter.formatToCEF(record, eventClassID, "info", severity, endpoint)

				if err := syslogClient.SendMessage(cefMessage); err != nil {
					fmt.Printf("  Error sending to syslog: %v\n", err)
					continue
				}

				// Track the latest timestamp from this batch
				if timestamp := extractTimestamp(record); !timestamp.IsZero() && timestamp.After(latestTimestamp) {
					latestTimestamp = timestamp
				}
			}
			
			// Update the last polled time for this org/endpoint combination
			if !latestTimestamp.IsZero() {
				stateManager.UpdateLastPolledTime(endpointKey, latestTimestamp)
				fmt.Printf("  Updated last polled time for %s to %s\n", endpointKey, latestTimestamp.Format("2006-01-02 15:04:05"))
			} else if len(data) > 0 {
				// If we got records but no timestamps, update to now
				stateManager.UpdateLastPolledTime(endpointKey, time.Now())
				fmt.Printf("  Updated last polled time for %s to current time (no timestamps in data)\n", endpointKey)
			} else if isFirstRun || lastPolledTime.IsZero() {
				// If this is first run and we got no data, set timestamp to now to avoid re-querying everything
				stateManager.UpdateLastPolledTime(endpointKey, time.Now())
				fmt.Printf("  Set initial timestamp for %s to current time (no data available)\n", endpointKey)
			}
		}
	}

	// Mark first run as complete if this was a first run
	if isFirstRun {
		stateManager.MarkFirstRunComplete()
		fmt.Printf("Initial comprehensive collection completed - switching to incremental mode\n")
	}

	// Save state
	if err := stateManager.Save(); err != nil {
		fmt.Printf("Error saving state: %v\n", err)
	}

	if isFirstRun {
		fmt.Printf("Completed initial collection - processed %d total records across %d organizations\n", 
			totalRecords, len(apiClient.organizations))
	} else {
		fmt.Printf("Completed incremental polling - processed %d total records across %d organizations\n", 
			totalRecords, len(apiClient.organizations))
	}
}

// Utility functions
func extractStringField(data map[string]interface{}, key, defaultValue string) string {
	if value, exists := data[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

func mapSeverity(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return 10
	case "MEDIUM", "WARNING", "WARN":
		return 6
	case "LOW", "INFO", "INFORMATION":
		return 3
	default:
		return 5
	}
}

func extractTimestamp(data map[string]interface{}) time.Time {
	// Look for activity time and creation time fields
	fields := []string{"activityTime", "createTime", "createdAt", "created_at", "timestamp", "occurredAt", "occurred_at", "time", "datetime"}
	
	for _, field := range fields {
		if value, exists := data[field]; exists {
			// Handle Unix timestamp (number)
			if num, ok := value.(float64); ok {
				return time.Unix(int64(num), 0)
			}
			// Handle string timestamp
			if str, ok := value.(string); ok {
				formats := []string{
					time.RFC3339,
					time.RFC3339Nano,
					"2006-01-02T15:04:05.000Z",
					"2006-01-02T15:04:05Z",
					"2006-01-02 15:04:05",
					"2006-01-02T15:04:05.000000Z",
				}
				
				for _, format := range formats {
					if t, err := time.Parse(format, str); err == nil {
						return t
					}
				}
			}
		}
	}
	
	return time.Time{}
}
