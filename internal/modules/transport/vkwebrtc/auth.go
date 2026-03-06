package vkwebrtc

import (
	"net/url"
)

const DefaultVKAppID = "6121396"

func GetAuthURL(appID string) string {
	if appID == "" {
		appID = DefaultVKAppID
	}

	u := url.Values{}
	u.Set("client_id", appID)
	u.Set("display", "page")
	u.Set("redirect_uri", "https://oauth.vk.com/blank.html")
	u.Set("scope", "offline")
	u.Set("response_type", "token")
	u.Set("v", "5.131")

	return "https://oauth.vk.com/authorize?" + u.Encode()
}

func AuthInstructions() string {
	return `
1. Open the generated link in your browser.
2. Click "Allow" (Разрешить).
3. Copy the text from the address bar (it will look like ...access_token=vk1.a.XYZ...).
4. Paste this token into your client configuration.
`
}
