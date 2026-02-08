# aws-idc-saml-capture

![Python](https://img.shields.io/badge/python-%3E%3D3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-0.1.0-orange)
![No Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

## Description

Local HTTP server that captures SAML assertions from AWS IAM Identity Center (formerly AWS SSO) customer managed SAML 2.0 applications for programmatic use with any SAML Service Provider.

## Why?

AWS IAM Identity Center (IdC) handles browser-based SAML SSO seamlessly — you click a customer managed SAML application tile, authenticate, and the SAML assertion is POSTed directly to the Service Provider's ACS URL. This works great for console/web access.

The problem arises when you need the raw SAML assertion for CLI or API use (e.g. `AssumeRoleWithSAML` for Alibaba Cloud, Snowflake token exchange, or any SP that accepts SAML assertions programmatically). IAM Identity Center doesn't expose SAML assertions through an API or CLI — the only delivery mechanism is the browser-based POST to the ACS endpoint. There's no `aws sso get-saml-assertion` equivalent.

One approach is to automate the browser with tools like Selenium or Playwright to intercept the SAML POST mid-flight. While this works, it comes with significant downsides: heavy dependencies (headless browser + driver), fragile selectors that break when AWS changes the login UI, difficulty handling MFA prompts, and complex session/cookie management. It's a lot of moving parts for what should be a simple capture.

This tool takes a lighter approach — instead of fighting the browser, it works *with* it. It starts a lightweight server on `localhost`, receives the SAML POST that would normally go to the SP, and makes the assertion available for programmatic use — letting you feed it into CLI tools, SDKs, or custom scripts. No browser automation, no extra dependencies, just Python stdlib.

Note that this means you'll typically need two separate IdC SAML applications per SP: one for browser-based access (ACS URL pointing to the SP) and one for CLI/programmatic use (ACS URL pointing to `http://localhost:<port>/saml/acs`). The attribute mappings are the same for both.

> **Important:** Because the ACS URL is set to `localhost`, the SAML response's `Recipient` field will also be `http://localhost:<port>/saml/acs`. Some Service Providers validate the `Recipient` value when you submit the assertion programmatically (e.g. AWS STS `AssumeRoleWithSAML` expects `Recipient` to be `https://signin.aws.amazon.com/saml`). This tool only works with SPs that either don't validate `Recipient` or accept the localhost value. See [Troubleshooting](#recipient-mismatch) for details.

## How It Works

```mermaid
sequenceDiagram
    participant User
    participant Local Server
    participant AWS IAM IdC
    participant Service Provider

    User-->>Local Server: 1. Start server
    User-->>AWS IAM IdC: 2. Open browser with SSO URL
    AWS IAM IdC-->>User: 3. Login + MFA
    User-->>AWS IAM IdC: 4. Authenticate
    AWS IAM IdC-->>Local Server: 5. POST SAML to localhost
    Local Server-->>User: 6. Success page
    User-->>Service Provider: 7. Use SAML assertion
    Service Provider-->>User: 8. Credentials
```

The server listens on `localhost:8443` (configurable via `--port`, but must match the port in your IAM Identity Center application's ACS URL), receives the SAML POST callback from AWS IAM Identity Center after you authenticate, extracts the assertion and attributes, and optionally saves them to a JSON file. You then use the captured assertion to authenticate with your target Service Provider (Alibaba Cloud, Snowflake, custom apps, etc.). The server always binds to `localhost` and cannot be changed — this is intentional to prevent accidental network exposure.

## Requirements

- Python >= 3.12
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Usage

### With uv (recommended)

```bash
# Run directly — no install needed
uv run saml_server.py \
  --sso-url "https://<directory-id>.awsapps.com/start/#/saml/default/<app-name>/<instance-id>"

# Or install as a CLI tool
uv venv
uv pip install -e .
aws-idc-saml-capture --sso-url "https://..."
```

### With pip

```bash
pip install -e .
aws-idc-saml-capture --sso-url "https://..."
```

### Basic

The `--sso-url` is the direct link to your SAML application in the AWS IAM Identity Center portal. You can obtain it by right-clicking the application tile in your SSO portal and copying the link address (see [Get the SSO URL](#get-the-sso-url)).

Alternatively, you can pass the IAM Identity Center access portal URL (`https://<directory-id>.awsapps.com/start`) — the browser will open the portal and you'll need to manually click the application tile to trigger the SAML flow.

```bash
python saml_server.py \
  --sso-url "https://<directory-id>.awsapps.com/start/#/saml/default/<app-name>/<instance-id>"
```

### Save to File

```bash
python saml_server.py --sso-url "https://..." -o saml.json
```

### Other Options

```bash
python saml_server.py --sso-url "https://..." \
  --port 9000          # custom port (default: 8443)
  --no-browser         # don't auto-open browser
  --print-saml         # print decoded SAML XML to stdout
  --timeout 120        # seconds to wait (default: 300)
  --quiet              # suppress info output
  --verbose            # debug-level output
```

### Output (saml.json)

```json
{
  "saml_response": "PHNhbWxwOlJlc3BvbnNlIC...base64...",
  "decoded_xml": "<samlp:Response ...>...</samlp:Response>",
  "assertion": "PHNhbWw6QXNzZXJ0aW9uIC...base64...",
  "relay_state": null,
  "attributes": {
    "Role": ["arn:aws:iam::123456:role/MyRole,arn:aws:iam::123456:saml-provider/MyIdP"],
    "RoleSessionName": ["user@example.com"]
  }
}
```

## AWS IAM Identity Center Setup

This is the IdP side — the same regardless of which Service Provider you're federating with.

### Create Custom SAML Application

See [Add and configure a customer managed application](https://docs.aws.amazon.com/singlesignon/latest/userguide/customermanagedapps-saml2-setup.html) in the AWS IAM Identity Center documentation.

### Get the SSO URL

1. Go to your SSO Portal: `https://<directory-id>.awsapps.com/start`
2. Right-click on the application → **Copy link address**
3. Format: `https://<directory-id>.awsapps.com/start/#/saml/default/<app-name>/<instance-id>`

---

## Service Provider Examples

### Alibaba Cloud RAM

<details>
<summary>Setup and usage</summary>

#### Alibaba Cloud Configuration

1. Go to **RAM Console** → **SSO** → **Role-based SSO**
2. **Create IdP** — upload AWS IAM Identity Center metadata XML
3. **Create RAM Role** — select the SAML IdP as trusted entity
4. Note the Role ARN (`acs:ram::<account-id>:role/<role-name>`)

#### AWS IAM IdC Application Settings

| Field | Value |
|-------|-------|
| Display name | `Alibaba Cloud CLI` |
| Application ACS URL | `http://localhost:8443/saml/acs` |
| Application SAML audience | `urn:alibaba:cloudcomputing:international` |

> The SAML audience differs by region: `urn:alibaba:cloudcomputing:international` for the international site and `urn:alibaba:cloudcomputing` for the China site. See [Configure Alibaba Cloud as a trusted SP for role-based SSO](https://www.alibabacloud.com/help/en/ram/configure-alibaba-cloud-as-a-trusted-sp-for-role-based-sso) for details.

#### Attribute Mappings

Refer to [SAML response for role-based SSO](https://www.alibabacloud.com/help/en/ram/saml-response-for-role-based-sso) for the full list of required attributes.

| Attribute in application | Maps to | Format |
|--------------------------|---------|--------|
| `https://www.aliyun.com/SAML-Role/Attributes/Role` | `acs:ram::<alibaba-account-id>:role/<role-name>,acs:ram::<alibaba-account-id>:saml-provider/<idp-name>` | unspecified |
| `https://www.aliyun.com/SAML-Role/Attributes/RoleSessionName` | `${user:email}` | unspecified |
| `https://www.aliyun.com/SAML-Role/Attributes/SessionDuration` | `3600` *(optional, seconds)* | unspecified |

#### Use the Captured Assertion

```bash
aliyun sts AssumeRoleWithSAML \
  --RoleArn "acs:ram::123456:role/test-role" \
  --SAMLProviderArn "acs:ram::123456:saml-provider/test-provider" \
  --SAMLAssertion "$(jq -r '.saml_response' saml.json)"
```

#### Browser Access (Optional)

For direct Alibaba Console access, create a second AWS IdC application with ACS URL `https://signin.alibabacloud.com/saml-role/sso` (same attribute mappings).

</details>

### Generic / Custom SP

<details>
<summary>Setup and usage</summary>

The server captures any standard SAML 2.0 POST binding response. To use it with any SP:

1. Create a custom SAML 2.0 application in AWS IAM Identity Center
2. Set ACS URL to `http://localhost:8443/saml/acs`
3. Set the SAML audience to whatever your SP expects
4. Configure attribute mappings per your SP's requirements
5. Run the server, authenticate, and use the captured `saml_response` (base64-encoded) with your SP's API or CLI

</details>

## Security Considerations

| Aspect                 | Status                 | Notes                                                                                                        |
| ---------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------ |
| SAML signature         | Signed by AWS IdC      | SP verifies the signature; the local server does not                                                         |
| Signature verification | Not performed locally  | The server captures the assertion as-is — validation happens on the SP side when you submit it               |
| Assertion lifetime     | Short (5–15 min)       | Must be used quickly; treat `saml.json` like a short-lived credential                                        |
| Transport              | HTTP (localhost only)  | Traffic does not leave the machine; some security scanners may flag the lack of HTTPS                        |
| Host binding           | Hardcoded to localhost | Cannot be changed — prevents accidental network exposure                                                     |
| Response headers       | CSP + nosniff          | `Content-Security-Policy` and `X-Content-Type-Options` headers on all HTML responses                         |
| Port binding           | First-come-first-served| A local process could theoretically bind the port before the server starts; low risk on single-user machines |
| File storage           | Optional, mode 0600    | `saml.json` is written with owner-only permissions; delete after use                                         |
| XML parsing            | stdlib ElementTree     | Safe on Python 3.12+ (Expat ≥ 2.6.0)                                                                        |
| Browser history        | SSO URL persists       | Not a credential leak (re-authentication required), but be aware on shared machines                          |

### Recommendations

- Don't commit `saml.json` to version control (already in `.gitignore`)
- Delete `saml.json` promptly after use — it's a bearer credential while the assertion is valid
- Use `--no-browser` in scripts for non-interactive use
- Verify the expected port is free before starting the server
- Rotate credentials regularly

## Troubleshooting

### Server times out

Default timeout is 300 seconds. Use `--timeout` to increase it, or check that the SSO URL is correct.

### "No SAMLResponse found in POST data"

Verify the ACS URL in your AWS IdC application matches exactly: `http://localhost:<port>/saml/acs`

### Browser shows error page

1. Ensure the server is running before clicking the SSO app
2. Check that the port is not in use by another process

### SAML assertion rejected by SP

1. Verify attribute mappings in AWS IdC match your SP's requirements
2. Check that the SAML audience matches what the SP expects
3. Ensure the assertion hasn't expired (use within 5 minutes)

### Recipient mismatch

When you configure the IdC application's ACS URL as `http://localhost:<port>/saml/acs`, the IdP bakes that value into the SAML response's `Recipient` field in `SubjectConfirmationData`. Some SPs validate this field when you submit the assertion via API/CLI.

For example, AWS STS `AssumeRoleWithSAML` requires `Recipient` to be `https://signin.aws.amazon.com/saml`. Since the captured assertion has `Recipient="http://localhost:8443/saml/acs"`, the call fails with `Not authorized to perform sts:AssumeRoleWithSAML`. This is a fundamental limitation — the same ACS URL can't serve as both the local capture endpoint and the SP's expected recipient.

You can check the `Recipient` value in your captured assertion:

```bash
jq -r '.decoded_xml' saml.json | grep -oP 'Recipient="[^"]*"'
```

This tool works with SPs that either don't validate `Recipient` or accept the localhost value (e.g. Alibaba Cloud `AssumeRoleWithSAML`).
