# F5 HTTPS Redirect 2025

An updated HTTP to HTTPS redirect iRule for F5 BIG-IP that fixes the issues with the legacy redirect solution.

## The Problem with Legacy Redirect iRules

F5's old [**_sys_https_redirect**](https://my.f5.com/manage/s/article/K10090418) iRule is simple and gets the job done, but it's starting to show its age:

1. **Always sends HTTP 302 redirects** - This changes POST requests to GET, breaking things like form submissions. We need HTTP 308 to preserve the request method.

2. **Breaks on IPv6 addresses** - The `getfield` command fails on IPv6 host headers like `[2001:db8::1]:8080`.

3. **No way to make exceptions** - Redirects everything unconditionally, which breaks ACME challenges, health checks, and webhooks that need HTTP.

4. **Everything is hardcoded** - No configuration parameters means editing the core logic for any change.

5. **Zero visibility** - No logging makes troubleshooting difficult.

6. **No port flexibility** - Can't handle non-standard port mappings like 8080→8443.

## The Solution: HTTPS Redirect 2025

This updated iRule addresses each limitation with specific technical improvements:

### Key Features

- **Host Header Validation** - Optional domain allowlist for security (first line of defense)
- **Configurable Exemptions** - Skip redirects for ACME challenges, health checks, and webhooks (disabled by default for security)
- **Three-Tier Logging** - Choose between none, standard, or debug logging
- **HTTP 308 Permanent Redirects** - Preserves request methods (POST, PUT, DELETE)
- **Flexible Port Mapping** - Define custom HTTP→HTTPS port mappings
- **Standardized Headers** - RFC-compliant cache control and connection headers prevent caching issues
- **Full IPv6 Support** - Correctly handles IPv6 addresses in brackets
- **Performance Optimized** - Static variables prevent CMP demotion
- **Variable Namespace Protection** - Prefixed variables prevent conflicts with other iRules
- **Deployment Error Detection** - Automatically detects and logs misconfiguration on HTTPS virtual servers

### How It Works

#### Proper HTTP 308 Redirects

```tcl
set static::httpsredirect_redirect_code 308
HTTP::respond $static::httpsredirect_redirect_code Location $redirect_location
```

HTTP 308 tells browsers "permanently moved, preserve the request method" - exactly what we need.

#### Robust IPv6 Handling

```tcl
# Process IPv6 addresses in brackets (e.g., [2001:db8::1]:8080)
if {[string match {\[*\]*} $raw_host]} {
    # Extract IPv6 address from brackets
    set bracket_end [string first "\]" $raw_host]
    if {$bracket_end > 0} {
        set ipv6_addr [string range $raw_host 1 [expr {$bracket_end - 1}]]
        # Set host to IPv6 with brackets preserved
        set host "\[$ipv6_addr\]"
    }
}
```

Inline IPv6 processing correctly handles bracketed addresses and port extraction.

#### Smart Exemptions (Opt-in for Security)

```tcl
# Exemptions are disabled by default for security
set static::httpsredirect_exemption_processing 0  # Change to 1 to enable

set static::httpsredirect_exemption_paths {
    "/.well-known/acme-challenge/*"
    "/health"
    "/status"
    "/ping"
    "/api/webhook/*"
}
```

Define paths that bypass redirects for Let's Encrypt, monitoring, and webhooks. **Note:** Exemptions are disabled by default for enhanced security. Enable only if needed.

#### Flexible Port Mapping

```tcl
array set static::httpsredirect_port_mapping {
    80    443
    8080  8443
    8888  9443
    8000  8443
    3000  3443
}
```

Map any HTTP port to its HTTPS equivalent.

#### Host Validation Security

```tcl
set static::httpsredirect_valid_hosts {
    "mysite.com"
    "www.mysite.com"
    "api.mysite.com"
}
```

Optional domain allowlist for additional security.

#### Standardized Redirect Headers

```tcl
set static::httpsredirect_cache_control "no-cache, no-store, must-revalidate"
set static::httpsredirect_connection "close"
```

RFC-compliant headers prevent caching issues and ensure clean redirects.

## Deployment

Deploy directly to your HTTP virtual server with minimal configuration required.

### Installation

1. **Review Configuration** - Edit the `RULE_INIT` section to customize:
   - Enable exemptions if needed (disabled by default for security)
   - Exemption paths for your environment
   - Port mappings if using non-standard ports
   - Host validation domains (or leave as "*" for all hosts)
   - Logging level for your needs

2. **Deploy to HTTP Virtual Server ONLY** - Attach the iRule to your HTTP virtual server (typically port 80)
   - **Important:** Do NOT attach to HTTPS virtual servers - the iRule will detect this error and log warnings

3. **Verify Operation** - Test redirects and confirm exemptions work as expected (if enabled)

The iRule immediately begins handling HTTP→HTTPS redirects with security-first defaults.

### Configuration Options

All configuration is centralized in the `RULE_INIT` section:

```tcl
# Core redirect settings
set static::httpsredirect_redirect_enabled 1
set static::httpsredirect_redirect_code 308
set static::httpsredirect_default_https_port 443

# Logging: "none", "standard", or "debug"
set static::httpsredirect_log_level "standard"

# Exemptions (disabled by default for security)
set static::httpsredirect_exemption_processing 0  # Change to 1 to enable
set static::httpsredirect_exemption_paths {
    "/.well-known/acme-challenge/*"
    "/health"
}

# Host validation (use "*" to accept all)
set static::httpsredirect_valid_hosts {
    "*"
}

# Standardized headers
set static::httpsredirect_cache_control "no-cache, no-store, must-revalidate"
set static::httpsredirect_connection "close"
```

### Logging Levels

Three logging levels to choose from:

- **`"none"`** - No operational logging, errors only
- **`"standard"`** - Log redirects and exemption matches (recommended)  
- **`"debug"`** - Verbose logging including host processing and port mapping

Example standard logging output:
```
F5_HTTPS_Redirect_2025: Redirecting to https://www.example.com/login with code 308
F5_HTTPS_Redirect_2025: Exemption matched '/.well-known/acme-challenge/*' for /.well-known/acme-challenge/token123 - allowing passthrough
F5_HTTPS_Redirect_2025: DEPLOYMENT ERROR - iRule attached to HTTPS virtual server!
```

## Performance Considerations

- **Static Variables** - Using `static::` prevents CMP demotion
- **Early Returns** - Exempted paths exit immediately
- **Inline Processing** - Efficient host header processing without procedure overhead
- **Selective Logging** - Production systems can disable logging entirely

These optimizations ensure minimal latency impact on redirect operations.

## Variable Namespace Protection

The iRule uses prefixed variables (`static::httpsredirect_*`) to prevent conflicts in multi-iRule environments.

### Why This Matters

Static variables in F5 iRules are global across the entire BIG-IP system. Without proper namespacing, iRules can accidentally overwrite each other's variables.

### How We Protect Against This

All variables use the `httpsredirect_` prefix:
- `static::httpsredirect_redirect_code` instead of `static::redirect_code`
- `static::httpsredirect_port_mapping` instead of `static::port_mapping`

This ensures the iRule plays nicely with other iRules in your environment.

### Creating Your Own Version

To create a customized version with different settings:
1. Copy the iRule
2. Search/replace `httpsredirect_` with your own unique prefix
3. Deploy alongside the original without conflicts

## Howto: Create a Dedicated iRule for a Single Host

### Why Create a Dedicated iRule?

Creating a host-specific iRule provides:
- **Security isolation** - Each domain gets its own redirect logic
- **Custom configuration** - Different exemptions and settings per domain
- **Independent maintenance** - Update one domain without affecting others
- **Audit clarity** - Clear separation of redirect rules per application

### Step-by-Step Example: API Service with Webhooks

Let's create a dedicated iRule for `api.example.com` that needs webhook exemptions and ACME support.

#### 1. Copy and Rename the iRule

Copy `https_redirect_2025_v0_3_1.tcl` to a new file:
```
https_redirect_api_example_v1.tcl
```

#### 2. Replace the Variable Prefix

Search and replace all instances:
- Find: `httpsredirect_`
- Replace: `apiexample_`

This prevents variable conflicts when running multiple iRules.

#### 3. Configure Host Validation

```tcl
# Only accept requests for api.example.com
set static::apiexample_valid_hosts {
    "api.example.com"
}
```

#### 4. Enable and Configure Exemptions

```tcl
# Enable path exemptions for this specific host
set static::apiexample_exemption_processing 1

# Define paths that should NOT redirect
set static::apiexample_exemption_paths {
    "/.well-known/acme-challenge/*"  # Let's Encrypt certificates
    "/webhooks/*"                     # Incoming webhooks from partners
    "/health"                         # Load balancer health checks
    "/api/v1/callbacks/*"            # API callbacks that require HTTP
}
```

#### 5. Customize Port Mapping (if needed)

```tcl
# API service runs on port 8080->8443
array set static::apiexample_port_mapping {
    80    443
    8080  8443
}
```

#### 6. Deploy to Virtual Server

1. Create the iRule in F5 Management Console
2. Attach ONLY to the HTTP virtual server for `api.example.com`
3. Test with:
   ```bash
   # Should redirect to HTTPS
   curl -I http://api.example.com/users
   
   # Should NOT redirect (exempted)
   curl -I http://api.example.com/webhooks/stripe
   ```

### Complete Example Configuration

Here's the key configuration section for your dedicated iRule:

```tcl
when RULE_INIT {
    # Unique prefix for this domain
    set static::apiexample_IRULE_VERSION "1.0.0"
    set static::apiexample_IRULE_NAME "API_Example_HTTPS_Redirect"
    
    # Core settings
    set static::apiexample_redirect_enabled 1
    
    # Host validation - ONLY api.example.com
    set static::apiexample_valid_hosts {
        "api.example.com"
    }
    
    # Enable exemptions for this API service
    set static::apiexample_exemption_processing 1
    
    # Paths that must remain HTTP
    set static::apiexample_exemption_paths {
        "/.well-known/acme-challenge/*"
        "/webhooks/*"
        "/health"
        "/api/v1/callbacks/*"
    }
    
    # Logging for troubleshooting
    set static::apiexample_log_level "standard"
    
    # Standard redirect settings
    set static::apiexample_redirect_code 308
    set static::apiexample_default_https_port 443
    
    # Headers
    set static::apiexample_cache_control "no-cache, no-store, must-revalidate"
    set static::apiexample_connection "close"
    
    # Port mapping for this service
    array set static::apiexample_port_mapping {
        80    443
        8080  8443
    }
}
```

### Benefits of This Approach

1. **Granular Control** - Each host gets exactly the exemptions it needs
2. **Security** - No risk of one domain's exemptions affecting another
3. **Maintainability** - Changes to one domain don't require testing all redirects
4. **Documentation** - Each iRule clearly documents its specific purpose

### When to Use Multiple iRules

Consider dedicated iRules when you have:
- Different exemption requirements per domain
- Varying security policies across applications  
- Multiple teams managing different services
- Compliance requirements for audit separation

## Compatibility and Requirements

- **BIG-IP Version**: Tested on 17.1.0+ but compatible with all [currently supported versions](https://my.f5.com/manage/s/article/K5903)
- **License**: Standard LTM license (no additional modules required)
- **Virtual Server**: HTTP virtual server with standard HTTP profile
- **SSL**: Not required on the HTTP virtual server (HTTPS traffic handled separately)

## Troubleshooting

### Redirects Not Working

1. Check the iRule is attached to the HTTP virtual server (not HTTPS)
2. Verify `redirect_enabled` is set to 1
3. Set logging to "debug" and check `/var/log/ltm` for details
4. Look for "DEPLOYMENT ERROR" messages if accidentally attached to HTTPS virtual server

### Exemptions Not Working

1. **Confirm `exemption_processing` is set to 1** (disabled by default for security)
2. Verify path patterns match exactly (use wildcards like `*` where needed)
3. Check logs for "Exemption matched" messages

### IPv6 Redirect Issues

1. Ensure clients are sending proper IPv6 host headers with brackets
2. Enable debug logging to see host header processing
3. Verify IPv6 is enabled on the virtual server

### Host Validation Rejecting Valid Requests

1. Check `valid_hosts` list includes all legitimate domains
2. Use "*" to disable validation during troubleshooting
3. Remember validation is case-sensitive

## Getting Help

- **Documentation**: Review inline comments in the iRule for detailed explanations
- **Community Support**: [F5 DevCentral](https://community.f5.com/) 
- **Bug Reports**: [Open a GitHub issue](https://github.com/tmarfil/f5-https-redirect-2025/issues)

## License

MIT License
