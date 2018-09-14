package ldap

// syncrepl.go

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

// https://tools.ietf.org/html/rfc4533
const (
	ControlTypeSyncRequest = "1.3.6.1.4.1.4203.1.9.1.1"
	ControlTypeSyncState   = "1.3.6.1.4.1.4203.1.9.1.2"
	ControlTypeSyncDone    = "1.3.6.1.4.1.4203.1.9.1.3"
	IntermediateResponseSyncInfo    = "1.3.6.1.4.1.4203.1.9.1.4"
)

// Sync Request mode
const (
	SyncModeRefreshOnly  = 1
	SyncModeRefreshAndPersist  = 3
)

type ControlSyncRequest struct {
	Criticality bool
	Mode        int    // ENUMERATED 1=refreshOnly 3=refreshAndPersist
	Cookie      []byte // syncCookie OPTIONAL
	ReloadHint  bool   // BOOLEAN DEFAULT FALSE
}

func init() {
	// ControlTypeMap maps controls to text descriptions
	ControlTypeMap[ControlTypeSyncRequest] = "Sync Request"
	ControlTypeMap[ControlTypeSyncState] = "Sync State"
	ControlTypeMap[ControlTypeSyncDone] = "Sync Done"

	// ControlTypeInstanceMap maps controls to empty instances
	ControlTypeInstanceMap[ControlTypeSyncRequest] = &ControlSyncRequest{}
	ControlTypeInstanceMap[ControlTypeSyncState] = &ControlSyncState{}
	ControlTypeInstanceMap[ControlTypeSyncDone] = &ControlSyncDone{}
}

func NewControlSyncRequest(criticality bool, mode int, cookie []byte, reloadHint bool) *ControlSyncRequest {
	return &ControlSyncRequest{
		Criticality: criticality,
		Mode:        mode,
		Cookie:      cookie,
		ReloadHint:  reloadHint,
	}
}

func (c *ControlSyncRequest) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeSyncRequest, "Control Type (Sync Request)"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Sync Request)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Sync Request Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(c.Mode), "Mode"))
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	seq.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.ReloadHint, "Reload Hint"))
	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

// Decode returns a control read from the given packet, or nil if no recognized control can be made
func (c *ControlSyncRequest) Decode(ControlType string, Criticality bool, value *ber.Packet) (Control, error) {
	return nil, nil
}

func (c *ControlSyncRequest) GetControlType() string {
	return ControlTypeSyncRequest
}

// String returns a human-readable description
// TODO Add a mode to string conversion
func (c *ControlSyncRequest) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Mode: %d  Cookie: %q",
		ControlTypeMap[ControlTypeSyncRequest],
		ControlTypeSyncRequest,
		c.Criticality,
		c.Mode,
		c.Cookie)
}

// Sync State
const (
	SyncStatePresent = 0
	SyncStateAdd = 1
	SyncStateModify = 2
	SyncStateDelete = 3
)

type ControlSyncState struct {
	State     uint32    // ENUMERATED 0=present, 1=add, 2=modify, 3=delete
	EntryUUID []byte // syncUUID
	Cookie    []byte // syncCookie OPTIONAL
}

func (c *ControlSyncState) GetControlType() string {
	return ControlTypeSyncState
}

func (c *ControlSyncState) Encode() *ber.Packet {
	return nil
}

// Decode returns a control read from the given packet, or nil if no recognized control can be made
func (c *ControlSyncState) Decode(ControlType string, Criticality bool, value *ber.Packet) (Control, error) {
	c = new(ControlSyncState)
	if value.Value != nil {
		valueChildren, err := ber.DecodePacketErr(value.Data.Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to decode data bytes: %s", err)
		}
		value.Data.Truncate(0)
		value.Value = nil
		value.AppendChild(valueChildren)
	}
	value = value.Children[0]
	c.State = uint32(value.Children[0].Value.(int64))
	c.EntryUUID = value.Children[1].Data.Bytes()
	if len(value.Children) > 2 {
		c.Cookie = value.Children[2].Data.Bytes()
    }
	return c, nil
}

func (c *ControlSyncState) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  State: %d  UUID: %q  Cookie: %q",
		ControlTypeMap[ControlTypeSyncState],
		ControlTypeSyncState,
		c.State,
		c.EntryUUID,
		c.Cookie)
}

type ControlSyncDone struct {
	Criticality    bool
	Cookie         []byte // syncCookie OPTIONAL
	RefreshDeletes bool   // BOOLEAN DEFAULT FALSE
}

func (c *ControlSyncDone) GetControlType() string {
	return ControlTypeSyncDone
}

func (c *ControlSyncDone) Encode() *ber.Packet {
	return nil
}

// Decode returns a control read from the given packet, or nil if no recognized control can be made
func (c *ControlSyncDone) Decode(ControlType string, Criticality bool, value *ber.Packet) (Control, error) {
	c = new(ControlSyncDone)
	c.Criticality = Criticality
	if value.Value != nil {
		valueChildren, err := ber.DecodePacketErr(value.Data.Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to decode data bytes: %s", err)
		}
		value.Data.Truncate(0)
		value.Value = nil
		value.AppendChild(valueChildren)
	}
	value = value.Children[0]
	c.Cookie = value.Children[0].Data.Bytes()
	//c.RefreshDeletes = uint32(value.Children[0].Value.(int64))
	return c, nil
}

func (c *ControlSyncDone) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Cookie: %q  Refresh Deletes: %t",
		ControlTypeMap[ControlTypeSyncDone],
		ControlTypeSyncDone,
		c.Cookie,
		c.RefreshDeletes)
}

func (l *Conn) SyncReplRefreshOnly(searchRequest *SearchRequest, cookie []byte) (*SearchResult, error) {
	// Find and update existing control or add a new one
  syncRequest := FindControl(searchRequest.Controls, ControlTypeSyncRequest)
  if syncRequest == nil {
        // Criticality, Mode, Cookie, ReloadHint
        syncRequest = NewControlSyncRequest(false, SyncModeRefreshOnly, cookie, false)
        searchRequest.Controls = append(searchRequest.Controls, syncRequest)
  } else {
		syncRequest.(*ControlSyncRequest).Cookie = cookie
  }
   
	msgCtx, err := l.issueSearchRequest(searchRequest)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	sr, err := l.fetchSearchResult(msgCtx)
	if err != nil {
		return nil, err
	}

	return sr, nil
}

