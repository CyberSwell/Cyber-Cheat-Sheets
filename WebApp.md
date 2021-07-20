# Web App Techniques

## 1. OAuth
### 1.1 OAuth Enumeration
- Verison 1.a (legacy) and 2.0 differ vastly, since 2.0 was written from scratch.
- Typically spotted when sites allow logins via social media/ other websites.

### 1.2 Authentication Bypass via OAuth Implicit Flow
- Issues: 
  - Access token is sent from OAuth service to client webapp via user's browser as URL fragment, which is parsed via JavaScript.
  - Token & user data sent to server to authenticate, and session cookie is generated without authenticating token with user data.
    - Victim webapp `implicitly` trusts the token without validating it.
  - Data sent alongside auth token can be altered to arbitrarily impersonate users without valid password.
- Exploitation:
  - Auth flow begins with GET request to `/authentication` endpoint, with parameters `client_id`, `redirect_uri`, and/or `response_type`.
  - Look for POST request back to victim site with JSON that includes a `token` field.
  - Change `email`, `username`, or other data in JSON to that of another user and resend request.
