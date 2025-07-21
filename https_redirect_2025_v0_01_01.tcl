# ============================================================================

# F5 HTTPS Redirect 2025 v0.01.01 - REFACTORED UNTESTED

# ============================================================================

# Unified HTTP/HTTPS iRule with configurable redirect and security headers.

# 

# DEPLOYMENT STRATEGY:

# - Always deploy to HTTP virtual server (port 80) for redirect functionality

# - Deploy to HTTPS virtual server (port 443) ONLY when security_headers_enabled=1

# 

# WHY deploy to HTTPS VS when security headers enabled?

# - Ensures consistent security headers whether user arrives via redirect or direct HTTPS

# - Prevents security policy gaps for users bypassing HTTP redirect

# - Single source of truth for security header configuration

# - No deployment when headers disabled = no unnecessary processing overhead

# 

# Context-aware processing with minimal performance impact.

# Supports ACME challenges, health checks, webhooks, and custom exemptions.

# ============================================================================

when RULE_INIT {
# ========================================================================
# GLOBAL CONFIGURATION - Set once when rule loads
# ========================================================================
set static::IRULE_VERSION “0.01.01”
set static::IRULE_NAME “F5_HTTPS_Redirect_2025_Unified”

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
# HOST HEADER PROCESSING FOR REDIRECT
# ========================================================================

# Extract and clean host header for redirect URL construction
set host [HTTP::host]

if {$static::debug_logging} {
    log local0. "$static::IRULE_NAME: Original host header: '$host'"
}

# Handle IPv6 addresses in brackets (e.g., [2001:db8::1]:8080)
if {[string match {\[*\]*} $host]} {
    if {$static::debug_logging} {
        log local0. "$static::IRULE_NAME: IPv6 pattern detected in host: '$host'"
    }
    
    # Extract IPv6 address and port if present
    set bracket_end [string first "\]" $host]
    
    if {$static::debug_logging} {
        log local0. "$static::IRULE_NAME: Bracket end position: $bracket_end"
    }
    
    if {$bracket_end > 0} {
        set ipv6_addr [string range $host 1 [expr {$bracket_end - 1}]]
        
        if {$static::debug_logging} {
            log local0. "$static::IRULE_NAME: Extracted IPv6 address: '$ipv6_addr'"
        }
        
        # Check for port after closing bracket
        if {[string first ":" $host [expr {$bracket_end + 1}]] > -1} {
            # Has port, extract it but don't use it (we'll use configured HTTPS port)
            set port_start [expr {$bracket_end + 2}]
            set orig_port [string range $host $port_start end]
            
            if {$static::debug_logging} {
                log local0. "$static::IRULE_NAME: Found port: '$orig_port'"
            }
            
            # Use the IPv6 address with brackets for redirect
            set host "\[$ipv6_addr\]"
        } else {
            # No port specified, just use the IPv6 address with brackets
            set host "\[$ipv6_addr\]"
        }
        
        if {$static::debug_logging} {
            log local0. "$static::IRULE_NAME: Final processed host: '$host'"
        }
    } else {
        # Malformed IPv6, use as-is
        # This handles edge cases where bracket parsing fails
        if {$static::debug_logging} {
            log local0. "$static::IRULE_NAME: IPv6 bracket parsing failed, using original host"
        }
    }
} else {
    # Handle regular hostnames and IPv4 addresses
    # Remove port if present (we'll use our configured HTTPS port)
    if {$static::debug_logging} {
        log local0. "$static::IRULE_NAME: Processing regular hostname: '$host'"
    }
    
    set colon_pos [string first ":" $host]
    if {$colon_pos > -1} {
        if {$static::debug_logging} {
            log local0. "$static::IRULE_NAME: Found colon at position: $colon_pos"
        }
        set host [string range $host 0 [expr {$colon_pos - 1}]]
        if {$static::debug_logging} {
            log local0. "$static::IRULE_NAME: Host after port removal: '$host'"
        }
    }
}

# ========================================================================
# REDIRECT URL CONSTRUCTION AND RESPONSE
# ========================================================================

# Construct the HTTPS URL
set uri [HTTP::uri]
if {$static::https_port != 443} {
    set redirect_location "https://${host}:${static::https_port}${uri}"
} else {
    set redirect_location "https://${host}${uri}"
}

# Log the redirect
log local0. "$static::IRULE_NAME: Redirecting to $redirect_location with code $static::redirect_code"

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