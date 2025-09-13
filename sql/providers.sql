INSERT INTO oauth_clients (
    provider, client_id, client_secret, redirect_uri, scopes, auth_url, token_url
) VALUES (
  'google',
  '<GoogleAPIClientID>',
  '<GoogleAPIClientSecret>',
  'http://localhost:9090/callback?provider=google',
  'openid,email,profile,https://mail.google.com/',
  'https://accounts.google.com/o/oauth2/auth',
  'https://oauth2.googleapis.com/token'
);

INSERT INTO oauth_clients (
    provider, client_id, client_secret, redirect_uri, scopes, auth_url, token_url
) VALUES (
    'microsoft',
    '<AzureAPIClientID>',
    '<AzureAPIClientSecret>',
    'http://localhost:9090/callback?provider=microsoft',
    'openid,email,offline_access,IMAP.AccessAsUser.All,SMTP.Send',
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    'https://login.microsoftonline.com/common/oauth2/v2.0/token'
);
