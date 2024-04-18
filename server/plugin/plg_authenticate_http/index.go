package plg_authenticate_passthrough

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	. "github.com/mickael-kerjean/filestash/server/common"
)

func init() {
	Hooks.Register.AuthenticationMiddleware("http", Admin{})
}

type Admin struct{}

func (this Admin) Setup() Form {
	return Form{
		Elmnts: []FormElement{
			{
				Name:  "type",
				Type:  "hidden",
				Value: "http",
			},
			{
				Name:  "strategy",
				Type:  "select",
				Value: "direct",
				Opts:  []string{"direct", "password_only", "username_and_password"},
				Description: `This plugin has 3 base strategies:
1. The 'direct' strategy will redirect the user to your storage without asking for anything and use whatever is configured in the attribute mapping section.
2. The 'password_only' strategy will redirect the user to a page asking for a password which you can map to a field in the attribute mapping section like this: {{ .password }}
3. The 'username_and_password' strategy is similar to the 'password_only' strategy but you will see in the login page both a username and password field which can be used fom the attribute mapping section like this: {{ .user }} {{ .password }}`,
			},
			{
				Name: "auth_url",
				Type: "text",
				Placeholder: `http://auth.example.org`,
				Default: "",
				Description: `The URL that checks the credentials:
A POST request is made to that URL when a user attempts to log-in with the 'user' and 'password' fields provided as JSON. If the response is 200 then the authorization is considered valid, else it is invalid. The response must be a JSON object containing the keys that will serve as template for the backend, generally 'user' templated as {{ .user }} and 'password' templated as {{ .password }}`,
			},
		},
	}
}

func (this Admin) EntryPoint(idpParams map[string]string, req *http.Request, res http.ResponseWriter) error {
	res.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch idpParams["strategy"] {
	case "direct":
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(Page(`<h2 style="display:none;">PASSTHROUGH</h2><script>location.href = "/api/session/auth/"</script>`)))
	case "password_only":
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(Page(`
      <form action="/api/session/auth/" method="post">
        <label>
          <input type="password" name="password" value="" placeholder="Password" />
        </label>
        <button>CONNECT</button>
      </form>`)))
	case "username_and_password":
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(Page(`
      <form action="/api/session/auth/" method="post">
        <label>
          <input type="text" name="user" value="" placeholder="User" />
        </label>
        <label>
          <input type="password" name="password" value="" placeholder="Password" />
        </label>
        <button>CONNECT</button>
      </form>`)))
	default:
		res.WriteHeader(http.StatusNotFound)
		res.Write([]byte(Page(fmt.Sprintf("Unknown strategy: '%s'", idpParams["strategy"]))))
	}
	return nil
}

func (this Admin) Callback(formData map[string]string, idpParams map[string]string, _ http.ResponseWriter) (map[string]string, error) {
	result := map[string]string{}

	encoded, err := json.Marshal(map[string]string{
		"user":     formData["user"],
		"password": formData["password"],
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, idpParams["auth_url"], bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
