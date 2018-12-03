INSERT INTO OAUTH_CLIENT_DETAILS
(client_id, resource_ids, client_secret, `scope`, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, additional_information, autoapprove)
VALUES('front-app', NULL, NULL, 'operate', 'implicit', 'http://localhost/tonr2/sparklr/photos', 'ROLE_USER', 60, NULL, NULL, 'true');
