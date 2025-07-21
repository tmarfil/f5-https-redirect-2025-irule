# ============================================================================

# F5 HTTPS Redirect 2025 v0.01.01 - REFACTORED UNTESTED

# ============================================================================

# Unified HTTP/HTTPS iRule with configurable redirect and security headers.

# 

# DEPLOYMENT STRATEGY:

# - Always deploy to HTTP virtual server (port 80) for redirect functionality

# - Deploy to HTTPS virtual server (port 443) ONLY when security_headers_enabled=1

# ============================================================================

when RULE_INIT {
# ========================================================================
# GLOBAL CONFIGURATION - Set once when rule loads
# ========================================================================
set static::IRULE_VERSION “0.01.01”
set static::IRULE_NAME “F5_HTTPS_Redirect_2025”

```
# Feature toggles - Enable/disable functionality independently
set static::redirect_enabled 1
set static::security_headers_enabled 0
set static::exemption_processing 1
set static::debug_logging 0

# Redirect configuration
set static::redirect_code 308
set static::https_port 443

# Exemption paths - compiled once for performance
set static::exemption_paths [list \
    "/.well-known/acme-challenge/*" \
    "/health" \
    "/status" \
    "/ping" \
    "/api/webhook/*" \
]

# Security headers configuration
# Set to empty string "" to disable individual headers
set static::hsts_header "max-age=31536000; includeSubDomains; preload"
set static::frame_options_header "DENY"
set static::content_type_options_header "nosniff"
set static::xss_protection_header "1; mode=block"
set static::referrer_policy_header "strict-origin-when-cross-origin"

# Pre-compile security headers for HTTP_RESPONSE efficiency
array set static::security_headers {}
if {$static::hsts_header ne ""} {
    set static::security_headers(Strict-Transport-Security) $static::hsts_header
}
if {$static::frame_options_header ne ""} {
    set static::security_headers(X-Frame-Options) $static::frame_options_header
}
if {$static::content_type_options_header ne ""} {
    set static::security_headers(X-Content-Type-Options) $static::content_type_options_header
}
if {$static::xss_protection_header ne ""} {
    set static::security_headers(X-XSS-Protection) $static::xss_protection_header
}
if {$static::referrer_policy_header ne ""} {
    set static::security_headers(Referrer-Policy) $static::referrer_policy_header
}

if {$static::debug_logging} {
    log local0. "$static::IRULE_NAME v$static::IRULE_VERSION: Rule initialized"
}
```

}

when HTTP_REQUEST {
# ========================================================================
# RUNTIME CONTEXT DETECTION - Simplified
# ========================================================================
set local_port [TCP::local_port]
set is_https_vs [expr {$local_port == 443 || $local_port == 8443}]

```
if {$static::debug_logging} {
    log local0. "$static::IRULE_NAME: Context - Port:$local_port HTTPS:$is_https_vs URI:[HTTP::uri]"
}

# ========================================================================
# HTTPS VIRTUAL SERVER PROCESSING (Early Exit)
# ========================================================================
if {$is_https_vs} {
    # HTTPS virtual servers: Allow all requests to pass through
    # Security headers will be added in HTTP_RESPONSE event if enabled
    return
}

# ========================================================================
# HTTP VIRTUAL SERVER PROCESSING
# ========================================================================

# Check if redirect functionality is disabled
if {!$static::redirect_enabled} {
    if {$static::debug_logging} {
        log local0. "$static::IRULE_NAME: Redirect disabled, passing through [HTTP::uri]"
    }
    return
}

# ========================================================================
# EXEMPTION PROCESSING - Optimized
# ========================================================================
if {$static::exemption_processing} {
    set uri [HTTP::uri]
    foreach pattern $static::exemption_paths {
        if {[string match $pattern $uri]} {
            if {$static::debug_logging} {
                log local0. "$static::IRULE_NAME: Exemption matched '$pattern' for $uri"
            }
            return
        }
    }
}

# ========================================================================
# HOST HEADER PROCESSING - Simplified
# ========================================================================
set host [HTTP::host]

# Use F5's built-in function to properly handle IPv6 and ports
if {[catch {set clean_host [getfield $host ":" 1]} result]} {
    # Fallback for complex cases (IPv6 with brackets)
    if {[string match {\[*\]*} $host]} {
        # Extract IPv6 address from brackets
        regexp {\[([^\]]+)\]} $host -> clean_host
        set clean_host "\[$clean_host\]"
    } else {
        set clean_host $host
    }
}

if {$static::debug_logging} {
    log local0. "$static::IRULE_NAME: Original host: '$host' -> Clean host: '$clean_host'"
}

# ========================================================================
# REDIRECT URL CONSTRUCTION AND RESPONSE
# ========================================================================

# Construct the HTTPS URL
set uri [HTTP::uri]
if {$static::https_port != 443} {
    set redirect_location "https://${clean_host}:${static::https_port}${uri}"
} else {
    set redirect_location "https://${clean_host}${uri}"
}

if {$static::debug_logging} {
    log local0. "$static::IRULE_NAME: Redirecting to $redirect_location"
}

# Send redirect response
if {$static::security_headers_enabled && [array size static::security_headers] > 0} {
    # Build response with security headers
    set response_headers [list \
        Location $redirect_location \
        Connection "close" \
        Cache-Control "no-cache, no-store, must-revalidate" \
    ]
    
    # Add security headers to response
    foreach {header_name header_value} [array get static::security_headers] {
        lappend response_headers $header_name $header_value
    }
    
    HTTP::respond $static::redirect_code {*}$response_headers
} else {
    # Send redirect without security headers
    HTTP::respond $static::redirect_code \
        Location $redirect_location \
        Connection "close" \
        Cache-Control "no-cache, no-store, must-revalidate"
}
```

}

when HTTP_RESPONSE {
# ========================================================================
# SECURITY HEADERS FOR RESPONSES
# ========================================================================

```
# Early exit if security headers disabled
if {!$static::security_headers_enabled || [array size static::security_headers] == 0} {
    return
}

# Add security headers to responses (HTTPS direct + HTTP exemptions)
foreach {header_name header_value} [array get static::security_headers] {
    HTTP::header replace $header_name $header_value
}

if {$static::debug_logging} {
    log local0. "$static::IRULE_NAME: Added [array size static::security_headers] security headers to response"
}
```

}