package client

const (
	OKTAConfigType                     = "oktaConfig"
	OKTAConfigFieldAccessMode          = "accessMode"
	OKTAConfigFieldAllowedPrincipalIDs = "allowedPrincipalIds"
	OKTAConfigFieldAnnotations         = "annotations"
	OKTAConfigFieldCreated             = "created"
	OKTAConfigFieldCreatorID           = "creatorId"
	OKTAConfigFieldDisplayNameField    = "displayNameField"
	OKTAConfigFieldEnabled             = "enabled"
	OKTAConfigFieldEntityID            = "entityID"
	OKTAConfigFieldGroupsField         = "groupsField"
	OKTAConfigFieldIDPMetadataContent  = "idpMetadataContent"
	OKTAConfigFieldLabels              = "labels"
	OKTAConfigFieldLogoutAllEnabled    = "logoutAllEnabled"
	OKTAConfigFieldLogoutAllForced     = "logoutAllForced"
	OKTAConfigFieldLogoutAllSupported  = "logoutAllSupported"
	OKTAConfigFieldName                = "name"
	OKTAConfigFieldOpenLdapConfig      = "openLdapConfig"
	OKTAConfigFieldOwnerReferences     = "ownerReferences"
	OKTAConfigFieldRancherAPIHost      = "rancherApiHost"
	OKTAConfigFieldRemoved             = "removed"
	OKTAConfigFieldSpCert              = "spCert"
	OKTAConfigFieldSpKey               = "spKey"
	OKTAConfigFieldStatus              = "status"
	OKTAConfigFieldType                = "type"
	OKTAConfigFieldUIDField            = "uidField"
	OKTAConfigFieldUUID                = "uuid"
	OKTAConfigFieldUserNameField       = "userNameField"
)

type OKTAConfig struct {
	AccessMode          string            `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	AllowedPrincipalIDs []string          `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	Annotations         map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Created             string            `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID           string            `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	DisplayNameField    string            `json:"displayNameField,omitempty" yaml:"displayNameField,omitempty"`
	Enabled             bool              `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	EntityID            string            `json:"entityID,omitempty" yaml:"entityID,omitempty"`
	GroupsField         string            `json:"groupsField,omitempty" yaml:"groupsField,omitempty"`
	IDPMetadataContent  string            `json:"idpMetadataContent,omitempty" yaml:"idpMetadataContent,omitempty"`
	Labels              map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	LogoutAllEnabled    bool              `json:"logoutAllEnabled,omitempty" yaml:"logoutAllEnabled,omitempty"`
	LogoutAllForced     bool              `json:"logoutAllForced,omitempty" yaml:"logoutAllForced,omitempty"`
	LogoutAllSupported  bool              `json:"logoutAllSupported,omitempty" yaml:"logoutAllSupported,omitempty"`
	Name                string            `json:"name,omitempty" yaml:"name,omitempty"`
	OpenLdapConfig      *LdapFields       `json:"openLdapConfig,omitempty" yaml:"openLdapConfig,omitempty"`
	OwnerReferences     []OwnerReference  `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	RancherAPIHost      string            `json:"rancherApiHost,omitempty" yaml:"rancherApiHost,omitempty"`
	Removed             string            `json:"removed,omitempty" yaml:"removed,omitempty"`
	SpCert              string            `json:"spCert,omitempty" yaml:"spCert,omitempty"`
	SpKey               string            `json:"spKey,omitempty" yaml:"spKey,omitempty"`
	Status              *AuthConfigStatus `json:"status,omitempty" yaml:"status,omitempty"`
	Type                string            `json:"type,omitempty" yaml:"type,omitempty"`
	UIDField            string            `json:"uidField,omitempty" yaml:"uidField,omitempty"`
	UUID                string            `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	UserNameField       string            `json:"userNameField,omitempty" yaml:"userNameField,omitempty"`
}
