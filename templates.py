"""HTML page templates for the SAML authentication server.

Templates use :class:`string.Template` for safe ``$variable`` substitution.
Unlike ``str.format()`` or f-strings, ``string.Template`` only performs simple
placeholder replacement — it cannot evaluate expressions or access object
attributes, which eliminates template-injection risks.

All dynamic values must still be passed through :func:`html.escape` before
substitution to prevent XSS.
"""

from string import Template

__all__: list[str] = [
    "ERROR_PAGE_TEMPLATE",
    "SUCCESS_PAGE_TEMPLATE",
    "WAITING_PAGE_TEMPLATE",
]

#: HTML page shown while the server awaits the SAML callback.
WAITING_PAGE_TEMPLATE: str = """\
<!DOCTYPE html>
<html>
<head>
    <title>SAML Authentication - Waiting</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db;
                   border-radius: 50%; width: 40px; height: 40px;
                   animation: spin 1s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .status { color: #666; }
    </style>
</head>
<body>
    <h1>🔐 SAML Authentication Server</h1>
    <div class="spinner"></div>
    <p class="status">Waiting for SAML response from AWS IAM Identity Center...</p>
    <p>Please complete authentication in your browser.</p>
    <script>
        setInterval(function() {
            fetch("/status").then(r => r.json()).then(data => {
                if (data.status === "received") { location.reload(); }
            }).catch(() => {});
        }, 2000);
    </script>
</body>
</html>"""

#: HTML page rendered after a SAML response is successfully captured.
#: Substitution variables: ``$attr_table``, ``$relay_state``.
SUCCESS_PAGE_TEMPLATE: Template = Template("""\
<!DOCTYPE html>
<html>
<head>
    <title>SAML Authentication - Success</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               max-width: 800px; margin: 50px auto; padding: 20px; }
        .success { color: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .note { background: #e8f4fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1 class="success">✅ Authentication Successful!</h1>
    <p>SAML response has been received and processed.</p>

    <div class="note">
        <strong>Note:</strong> You can close this browser tab.
        The SAML assertion has been captured by the local server.
    </div>

    $attr_table

    <p><small>Relay State: <code>$relay_state</code></small></p>

    <script>
        // Auto-close after 5 seconds (optional)
        // setTimeout(() => window.close(), 5000);
    </script>
</body>
</html>""")

#: HTML page rendered when SAML processing fails.
#: Substitution variables: ``$error_message``.
ERROR_PAGE_TEMPLATE: Template = Template("""\
<!DOCTYPE html>
<html>
<head>
    <title>SAML Authentication - Error</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .error { color: #e74c3c; }
        .message { background: #fdf2f2; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1 class="error">❌ Authentication Error</h1>
    <div class="message">$error_message</div>
    <p>Please try again or check the server logs for more details.</p>
</body>
</html>""")
