package providers

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newMSADV3Provider() *MSADV3Provider {
	return NewMSADV3Provider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
		})
}

func TestMSADV3ProviderDefaults(t *testing.T) {
	p := newMSADV3Provider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "MSADV3", p.Data().ProviderName)
	assert.Equal(t, "https://adfs.local/adfs/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://adfs.local/adfs/oauth2/token",
		p.Data().RedeemURL.String())
}

func TestMSADV3ProviderOverrides(t *testing.T) {
	p := NewMSADV3Provider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
		})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "MSADV3", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
}

func TestMSADV3ProviderGetEmailAddress(t *testing.T) {
	p := newMSADV3Provider()
	const jsonAccessToken = `{"winaccountname": "me@supree.co.uk", "email": "me@supree.co.uk", "iat":1518706229, "exp":1518709829 }`
	accesstoken := base64.URLEncoding.EncodeToString([]byte(jsonAccessToken))

	session := &SessionState{AccessToken: "ignored_prefix." + accesstoken}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "me@supree.co.uk", email)
}

func TestMSADV3ProviderGetUserName(t *testing.T) {
	p := newMSADV3Provider()
	const jsonAccessToken = `{"winaccountname": "me@supree.co.uk", "email": "me@supree.co.uk", "iat":1518706229, "exp":1518709829 }`
	accesstoken := base64.URLEncoding.EncodeToString([]byte(jsonAccessToken))

	session := &SessionState{AccessToken: "ignored prefix." + accesstoken}
	user, err := p.GetUserName(session)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "me@supree.co.uk", user)
}

func TestMSADV3ProviderGetEmailAddressEmailMissing(t *testing.T) {
	p := newGoogleProvider()
	const jsonAccessToken = `{"winaccountname": "me@supree.co.uk", "notemail": "me@supree.co.uk", "iat":1518706229, "exp":1518709829 }`
	accesstoken := base64.URLEncoding.EncodeToString([]byte(jsonAccessToken))

	session := &SessionState{AccessToken: "ignored prefix." + accesstoken}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)

}

func TestMSADV3ProviderGetUserNameUserNameMissing(t *testing.T) {
	p := newGoogleProvider()
	const jsonAccessToken = `{"notwinaccountname": "me@supree.co.uk", "email": "me@supree.co.uk", "iat":1518706229, "exp":1518709829 }`
	accesstoken := base64.URLEncoding.EncodeToString([]byte(jsonAccessToken))

	session := &SessionState{AccessToken: "ignored prefix." + accesstoken}
	username, err := p.GetUserName(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", username)

}
