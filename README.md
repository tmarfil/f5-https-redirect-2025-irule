# F5 HTTPS Redirect iRule Update

F5's old [**_sys_https_redirect**](https://my.f5.com/manage/s/article/K10090418) iRule is simple and gets the job done, but it's starting to show its age. It has some issues handling today's web apps:

1. **It always sends a 302 redirect.** This changes POST requests to GET, breaking things like form submissions. We should use a 308 instead to preserve the request method.
2. **It chokes on IPv6 host headers.** If you have an IPv6 address like `[2001:db8::1]:8080`, the `getfield` command used to parse out the host will fail. We need a smarter way to handle that. 
3. **There's no way to make exceptions.** Sometimes you need HTTP for things like Let's Encrypt validation or health checks. The iRule redirects everything to HTTPS unconditionally.
4. **It doesn't set any security headers.** The redirect response is bare-bones. It's a missed chance to enable some extra protections.
5. **Everything is hardcoded.** Want to change something? There are no editable parameters. Not the most admin-friendly.
6. **Zero visibility.** If something isn't working right, good luck figuring out why. The iRule doesn't log anything for troubleshooting.

## How HTTPS Redirect 2025 solves this

Here's how the new iRule tackles these issues:

### Use a 308 redirect and preserve the request method

```tcl
set redirect_code 308  
HTTP::respond $redirect_code Location $redirect_location
```

A 308 status tells the browser "this resource has permanently moved to a new location, and you should use the same request method you used on the original request." Perfect for our needs.

### Handle IPv6 addresses properly

```tcl
if {[string match "\[*\]*" $host]} {
    set ipv6_end [string first "\]" $host]
    set ipv6_addr [string range $host 1 [expr {$ipv6_end - 1}]]
    # Complex IPv6 + port parsing logic
}  
```

We check if the host header starts with a bracket `[`, which indicates an IPv6 address. If it does, we find the closing bracket and extract everything between them as the IPv6 address. Then we can handle the port separately.

### Allow exceptions for certain paths

```tcl
set exemption_paths {
    "/.well-known/acme-challenge/*" 
    "/health"
    "/status"
    "/ping"
    "/api/webhook/*"
}
foreach pattern $exemption_paths {
    if {[string match $pattern $uri]} {
        return
    }
}
```

We define a list of paths that should be exempt from the redirect, like `/.well-known/acme-challenge/*` for Let's Encrypt. If the request URI matches any of those patterns, we just return and let the request through without redirecting.

### Add some security headers

```tcl
HTTP::respond $redirect_code Location $redirect_location \
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" \
    X-Frame-Options "DENY" \
    X-Content-Type-Options "nosniff" \
    X-XSS-Protection "1; mode=block" \  
    Referrer-Policy "strict-origin-when-cross-origin"
```

We can improve security by attaching a few key headers to the redirect response:

- `Strict-Transport-Security` to enforce HTTPS
- `X-Frame-Options` to prevent clickjacking
- `X-Content-Type-Options` to stop MIME sniffing vulnerabilities
- `X-XSS-Protection` to enable browser XSS filters
- `Referrer-Policy` to limit sensitive info in the `Referer` header

### Make the config user-friendly

```tcl
set redirect_code 308
set https_port 443 
set exemption_paths { ... }
```

Configuration options are pulled to the top of the iRule in a clearly marked section. This way admins can tweak the behavior without having to understand all the underlying logic.

### Add some logging

```tcl
log local0. "$::IRULE_NAME v$::IRULE_VERSION: Exemption matched '$pattern' for $uri"
log local0. "$::IRULE_NAME v$::IRULE_VERSION: Redirecting to $redirect_location"  
```

Logging statements use the standard syslog format, including the iRule name and version. This gives breadcrumbs to follow if troubleshooting a redirect issue.

## Deploying HTTPS Redirect 2025

### Basic Deployment 

The default behavior is designed for simplicity and performance:

1. Set `security_headers_enabled=0` in the iRule (this is the default)
2. Apply the iRule to the HTTP virtual server only (usually port 80)

That's it! With this setup:

- HTTP requests will redirect to HTTPS
- Exemption paths are honored 
- HTTPS traffic goes directly to the pool without being processed by the iRule

This matches the old **_sys_https_redirect** behavior, but with all the added benefits.

### Full Deployment with Security Headers

If you want to include security headers in the response, you can enable the headers on both redirect responses _and_ direct HTTPS traffic:

1. Set `security_headers_enabled=1` in the iRule 
2. Apply the iRule to *both* the HTTP and HTTPS virtual servers

Now the iRule will:

- Add security headers to HTTP redirect responses
- Allow HTTPS requests to pass through to the pool
- Add the same security headers to all HTTPS responses

## Compatibility and Requirements

HTTPS Redirect 2025 has been tested on BIG-IP 17.5.0 but should work on all [supported versions of BIG-IP](https://my.f5.com/manage/s/article/K5903).

The full feature set requires an HTTPS virtual server and client SSL profile. Legacy SSL profiles are supported.

No special licensing is required beyond the base BIG-IP LTM.

## Getting Help

For configuration and troubleshooting help:

- [F5 DevCentral](https://community.f5.com/) 
- [Open a GitHub issue](https://github.com/tmarfil/f5-https-redirect-2025/issues)

