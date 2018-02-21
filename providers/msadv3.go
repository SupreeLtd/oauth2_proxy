package providers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type MSADV3Provider struct {
	*ProviderData
	AdfsHost string
}

func NewMSADV3Provider(p *ProviderData) *MSADV3Provider {
	p.ProviderName = "MSADV3"

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "adfs.local",
			Path:   "/adfs/oauth2/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "adfs.local",
			Path:   "/adfs/oauth2/token",
		}
	}

	return &MSADV3Provider{ProviderData: p}
}

func (p *MSADV3Provider) Configure(adfshost string) {
	p.AdfsHost = adfshost

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   p.AdfsHost,
			Path:   "/adfs/oauth2/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   p.AdfsHost,
			Path:   "/adfs/oauth2/token",
		}
	}

}

func (p *MSADV3Provider) GetEmailAddress(s *SessionState) (string, error) {
	// var email string
	var err error

	if s.AccessToken == "" {
		return "1@1.com", errors.New("missing access token")
	}

	jwt := strings.Split(s.AccessToken, ".")
	fmt.Println(jwt[1])
	b, err := base64.RawURLEncoding.DecodeString(jwt[1])
	if err != nil {
		return "2@2.com", err
	}

	var email struct {
		Email          string `json:"email"`
		WinAccountName string `json:"winaccountname"`
		IssuedAt       int64  `json:"iat"`
		ExpiresAt      int64  `json:"exp"`
	}
	err = json.Unmarshal(b, &email)
	if err != nil {
		return "", err
	}
	if email.Email == "" {
		return "", errors.New("missing email")
	}
	return email.Email, nil
}

func (p *MSADV3Provider) GetUserName(s *SessionState) (string, error) {
	// var email string
	var err error

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	jwt := strings.Split(s.AccessToken, ".")
	b, err := base64.RawURLEncoding.DecodeString(jwt[1])
	if err != nil {
		return "", err
	}

	var winaccountname struct {
		Email          string `json:"email"`
		WinAccountName string `json:"winaccountname"`
		IssuedAt       int64  `json:"iat"`
		ExpiresAt      int64  `json:"exp"`
	}
	err = json.Unmarshal(b, &winaccountname)
	if err != nil {
		return "", err
	}
	if winaccountname.WinAccountName == "" {
		return "", errors.New("missing winaccountname")
	}
	return winaccountname.WinAccountName, nil
}
