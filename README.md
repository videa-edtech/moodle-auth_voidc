# Vloom OIDC Authentication Plugin for Moodle (`auth_voidc`)

A generic OpenID Connect (OIDC) authentication plugin for Moodle. Forked from [moodle-auth_oidc](https://github.com/microsoft/moodle-auth_oidc) and stripped down to work with any standards-compliant OIDC provider — Keycloak, Auth0, Okta, Google, etc.

## Installation

1. Clone or copy this plugin into `/auth/voidc` within your Moodle install:
   ```bash
   git clone https://github.com/videa-edtech/moodle-auth_voidc.git auth/voidc
   ```
2. Go to **Site Administration → Notifications** and follow the on-screen instructions to install.
3. Go to **Site Administration → Plugins → Authentication → Manage Authentication** and enable `voidc`.
4. Click the settings icon to configure the plugin.

## License

GPLv3 — see [LICENSE](LICENSE)

## Copyright

&copy; 2024 onwards Videa Edtech Jsc.

Originally forked from [moodle-auth_oidc](https://github.com/microsoft/moodle-auth_oidc) &copy; Microsoft, Inc.