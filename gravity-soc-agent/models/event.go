package models

import "time"

type Source struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	User     string `json:"user,omitempty"`
}

type Destination struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Domain string `json:"domain,omitempty"`
}

type Process struct {
	ID          int    `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	HashSHA256  string `json:"hash_sha256,omitempty"`
	ProcessGuid string `json:"process_guid,omitempty"`
	ParentImage string `json:"parent_image,omitempty"`
}

type Payload struct {
	DNSQueryType  string `json:"dns_query_type,omitempty"`
	SysmonEventID *int   `json:"sysmon_event_id,omitempty"`
	NXDomainBurst bool   `json:"nxdomain_burst,omitempty"`
	ARPNewDevice  bool   `json:"arp_new_device,omitempty"`
}

type Event struct {
	Timestamp   time.Time   `json:"timestamp"`
	AgentID     string      `json:"agent_id"`
	OS          string      `json:"os"`
	EventType   string      `json:"event_type"`
	Severity    string      `json:"severity"`
	Source      Source      `json:"source"`
	Destination Destination `json:"destination"`
	Process     Process     `json:"process"`
	Payload     Payload     `json:"payload"`
	RawMessage  string      `json:"raw_message"`
}
