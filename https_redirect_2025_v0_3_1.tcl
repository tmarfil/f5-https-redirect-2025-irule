# ============================================================================
# F5 HTTPS Redirect 2025 v0.3.1
# ============================================================================
# HTTP to HTTPS redirect iRule with configurable exemptions.
# Optimized for performance with static variables to prevent CMP demotion.
# Enhanced with port mapping array for flexible HTTP->HTTPS port redirects.
# 
# DEPLOYMENT STRATEGY:
# - Deploy to HTTP virtual server (port 80) ONLY for redirect functionality
# - Clean HTTP 308 redirects (RFC 7538) with standardized headers
#
# Context-aware processing with minimal performance impact.
# Supports ACME challenges, health checks, webhooks, and custom exemptions.
#
# CONFIGURATION:
# All configuration options are in the RULE_INIT section immediately below.
# Modify exemption paths, port mappings, and debug settings as needed.
# ============================================================================

when RULE_INIT {
    # ========================================================================
    # SYSTEM INITIALIZATION
    # ========================================================================
    # IMPORTANT: Variable Collision Prevention
    # static:: variables are shared across ALL iRules on the F5 system!
    # The prefix 'httpsredirect_' prevents conflicts with other iRules.
    # To create a new iRule: search/replace 'httpsredirect_' with your unique prefix.
    # ========================================================================
    set static::httpsredirect_IRULE_VERSION "0.3.1"
    set static::httpsredirect_IRULE_NAME "F5_HTTPS_Redirect_2025"
    
    # ========================================================================
    # DEPLOYMENT CONFIGURATION
    # ========================================================================
    
    # Feature toggles - Enable/disable functionality independently
    set static::httpsredirect_redirect_enabled 1

    # Host header validation (Security Boundary - checked FIRST)
    # Default: "*" = accept any host (no validation)
    # Security: Replace "*" with specific hosts to enable automatic validation
    # Host validation is INDEPENDENT of exemption_processing setting
    # Invalid hosts receive HTTP 403 Forbidden response
    # Example: {"mysite.com" "www.mysite.com" "api.mysite.com"}
    set static::httpsredirect_valid_hosts {
        "*"
    }

    # Path exemption processing: 0 = disabled (redirect all paths), 1 = enabled (allow exempted paths)
    # This ONLY controls path-based exemptions (e.g., ACME challenges, health checks)
    # Host validation is independent and automatic when valid_hosts is configured
    set static::httpsredirect_exemption_processing 0

    # Path exemptions (only processed when exemption_processing = 1)
    # These paths will NOT be redirected and will pass through to backend pool
    # Note: Path exemptions are checked AFTER host validation passes
    # Default: exemption_processing is disabled, all paths redirect to HTTPS
    set static::httpsredirect_exemption_paths {
        "/.well-known/acme-challenge/*"
        "/health"
        "/status" 
        "/ping"
        "/api/webhook/*"
    }

    # Logging levels: "none", "standard", "debug"
    # none = No operational logging, errors only
    # standard = Key events (redirects, exemptions, initialization)  
    # debug = Verbose details (host processing, IPv6 parsing, context)
    set static::httpsredirect_log_level "standard"
    
    # Redirect configuration (only used when redirect_enabled = 1)
    set static::httpsredirect_redirect_code 308
    set static::httpsredirect_default_https_port 443
    
    # Standardized redirect headers (RFC 7231 HTTP semantics, RFC 7234 HTTP caching)
    set static::httpsredirect_cache_control "no-cache, no-store, must-revalidate"
    set static::httpsredirect_connection "close"
    
    # HTTP to HTTPS port mapping
    # Maps source HTTP ports to destination HTTPS ports
    # If HTTP port is not in this mapping, uses default_https_port
    array set static::httpsredirect_port_mapping {
        80    443
        8080  8443
        8888  9443
        8000  8443
        3000  3443
    }
    
    # ========================================================================
    # END OF USER CONFIGURATION SECTION
    # ========================================================================
    # All user-configurable settings are defined above this point.
    # ========================================================================
    
    # ========================================================================
    # CONFIGURATION VALIDATION AND RUNTIME SETUP
    # ========================================================================
    
    # Validate logging level configuration
    set valid_log_levels [list "none" "standard" "debug"]
    if {[lsearch $valid_log_levels $static::httpsredirect_log_level] == -1} {
        log local0.error "$static::httpsredirect_IRULE_NAME: ERROR - Invalid log_level \
            '$static::httpsredirect_log_level'. Must be: none, standard, or debug. \
            Using 'standard'."
        set static::httpsredirect_log_level "standard"
    }
    
    # Helper variables for log level checking (must be static for HTTP_REQUEST access)
    set static::httpsredirect_log_standard [expr {
        $static::httpsredirect_log_level eq "standard" || 
        $static::httpsredirect_log_level eq "debug"
    }]
    set static::httpsredirect_log_debug [expr {$static::httpsredirect_log_level eq "debug"}]
    
    # Validate host configuration during RULE_INIT
    if {[llength $static::httpsredirect_valid_hosts] == 0} {
        log local0.error "$static::httpsredirect_IRULE_NAME: ERROR - \
            valid_hosts array is empty! Using wildcard mode."
        set static::httpsredirect_valid_hosts {"*"}
        set static::httpsredirect_host_validation_active 0
    } elseif {[lsearch -exact $static::httpsredirect_valid_hosts "*"] != -1} {
        if {[llength $static::httpsredirect_valid_hosts] > 1} {
            log local0.error "$static::httpsredirect_IRULE_NAME: ERROR - \
                valid_hosts contains '*' mixed with specific hosts! \
                Using wildcard mode only."
            set static::httpsredirect_valid_hosts {"*"}
        }
        set static::httpsredirect_host_validation_active 0
    } else {
        set static::httpsredirect_host_validation_active 1
        if {$static::httpsredirect_log_standard} {
            log local0.info "$static::httpsredirect_IRULE_NAME: \
                Host validation enabled for [llength $static::httpsredirect_valid_hosts] hosts"
        }
    }
    
    # Log initialization (show for standard and debug levels)
    if {$static::httpsredirect_log_standard} {
        log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
            Initialized - redirect_enabled=$static::httpsredirect_redirect_enabled, \
            host_validation=$static::httpsredirect_host_validation_active, \
            log_level=$static::httpsredirect_log_level, \
            port_mappings=[array size static::httpsredirect_port_mapping]"
    }
}

when HTTP_REQUEST {
    # ========================================================================
    # DEPLOYMENT ERROR DETECTION
    # ========================================================================
    # This iRule is designed for HTTP virtual servers ONLY (port 80)
    # If deployed on HTTPS virtual server, log error and exit
    # ========================================================================
    
    if {[PROFILE::exists clientssl]} {
        # ERROR: iRule deployed on HTTPS virtual server!
        log local0.error "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
            DEPLOYMENT ERROR - iRule attached to HTTPS virtual server! \
            This iRule should only be attached to HTTP (port 80) virtual servers. \
            Remove from HTTPS virtual server immediately."
        return
    }
    
    # Get local port for redirect mapping
    set local_port [TCP::local_port]
    
    # ========================================================================
    # REDIRECT PROCESSING
    # ========================================================================
    
    # Check if redirect functionality is disabled
    if {!$static::httpsredirect_redirect_enabled} {
        if {$static::httpsredirect_log_standard} {
            log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                Redirect disabled, passing through [HTTP::uri]"
        }
        return
    }
    
    # ========================================================================
    # HOST HEADER VALIDATION (Security Boundary)
    # ========================================================================
    # Validate host header BEFORE any exemption processing
    # This ensures security checks happen first
    # ========================================================================
    
    # Extract host header for validation
    set raw_host [HTTP::host]
    
    # Host header validation (if enabled) - validate BEFORE any other processing
    if {$static::httpsredirect_host_validation_active} {
        # Extract hostname without port for validation
        set validation_host $raw_host
        if {[string match {\[*\]*} $raw_host]} {
            # IPv6 format - extract just the address part
            set bracket_end [string first "\]" $raw_host]
            if {$bracket_end > 0} {
                set validation_host [string range $raw_host 1 [expr {$bracket_end - 1}]]
            }
        } else {
            # Regular hostname - remove port if present
            set colon_pos [string first ":" $raw_host]
            if {$colon_pos > -1} {
                set validation_host [string range $raw_host 0 [expr {$colon_pos - 1}]]
            }
        }
        
        if {[lsearch -exact $static::httpsredirect_valid_hosts $validation_host] == -1} {
            if {$static::httpsredirect_log_standard} {
                log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                    Invalid host '$validation_host' - rejecting request with 403"
            }
            HTTP::respond 403 content "Forbidden" "Content-Type" "text/plain"
            return
        }
    }
    
    # ========================================================================
    # PATH EXEMPTION PROCESSING
    # ========================================================================
    # Process path-based exemptions (e.g., ACME challenges, health checks)
    # Only checked AFTER host validation passes
    # ========================================================================
    
    # Get URI for exemption checking
    set uri [HTTP::uri]
    
    # Process path exemptions if enabled
    set is_exempt 0
    if {$static::httpsredirect_exemption_processing} {
        foreach pattern $static::httpsredirect_exemption_paths {
            if {[string match $pattern $uri]} {
                set is_exempt 1
                if {$static::httpsredirect_log_standard} {
                    log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                        Path exemption matched '$pattern' for $uri - allowing passthrough"
                }
                break
            }
        }
    }
    
    # If path is exempt, allow request to pass through to backend pool
    if {$is_exempt} {
        return
    }
    
    # ========================================================================
    # HOST HEADER PROCESSING
    # ========================================================================
    # Process IPv6 addresses and remove ports for clean redirect URLs
    # ========================================================================
    
    # Process IPv6 addresses in brackets (e.g., [2001:db8::1]:8080)
    if {[string match {\[*\]*} $raw_host]} {
        if {$static::httpsredirect_log_debug} {
            log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                IPv6 pattern detected in host: '$raw_host'"
        }
        
        # Extract IPv6 address from brackets
        set bracket_end [string first "\]" $raw_host]
        if {$bracket_end > 0} {
            set ipv6_addr [string range $raw_host 1 [expr {$bracket_end - 1}]]
            
            if {$static::httpsredirect_log_debug} {
                log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                    Extracted IPv6 address: '$ipv6_addr'"
            }
            
            # Check for port after closing bracket
            if {[string first ":" $raw_host [expr {$bracket_end + 1}]] > -1} {
                # Has port, but we'll strip it for redirect
                if {$static::httpsredirect_log_debug} {
                    set port_start [expr {$bracket_end + 2}]
                    set orig_port [string range $raw_host $port_start end]
                    log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                        Found port '$orig_port', returning IPv6 host without port for redirect"
                }
            }
            
            # Set host to IPv6 with brackets preserved
            set host "\[$ipv6_addr\]"
        } else {
            # Malformed IPv6, use as-is
            if {$static::httpsredirect_log_debug} {
                log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                    IPv6 bracket parsing failed, using original host"
            }
            set host $raw_host
        }
    } else {
        # Handle regular hostnames and IPv4 addresses
        # Remove port if present (we'll use our configured HTTPS port)
        if {$static::httpsredirect_log_debug} {
            log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                Processing regular hostname: '$raw_host'"
        }
        
        set colon_pos [string first ":" $raw_host]
        if {$colon_pos > -1} {
            set host [string range $raw_host 0 [expr {$colon_pos - 1}]]
            if {$static::httpsredirect_log_debug} {
                log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                    Host after port removal: '$host'"
            }
        } else {
            set host $raw_host
        }
    }
    
    # Log the transformation if debug enabled and host changed
    if {$static::httpsredirect_log_debug && ($raw_host ne $host)} {
        log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
            Processed host from '$raw_host' to '$host'"
    }
    
    # ========================================================================
    # REDIRECT PORT DETERMINATION
    # ========================================================================
    
    # Determine target HTTPS port based on current HTTP port
    if {[info exists static::httpsredirect_port_mapping($local_port)]} {
        set target_https_port $static::httpsredirect_port_mapping($local_port)
        if {$static::httpsredirect_log_debug} {
            log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                Using port mapping: $local_port -> $target_https_port"
        }
    } else {
        set target_https_port $static::httpsredirect_default_https_port
        if {$static::httpsredirect_log_debug} {
            log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
                No port mapping for $local_port, using default: $target_https_port"
        }
    }
    
    # ========================================================================
    # REDIRECT URL CONSTRUCTION AND RESPONSE
    # ========================================================================
    
    # Construct the HTTPS URL
    if {$target_https_port != 443} {
        set redirect_location "https://${host}:${target_https_port}${uri}"
    } else {
        set redirect_location "https://${host}${uri}"
    }
    
    # Log the redirect (Standard level - key operational event)
    if {$static::httpsredirect_log_standard} {
        log local0. "$static::httpsredirect_IRULE_NAME v$static::httpsredirect_IRULE_VERSION: \
            Redirecting to $redirect_location with code $static::httpsredirect_redirect_code"
    }
    
    # Send HTTP 308 redirect response (RFC 7538) with standardized headers
    HTTP::respond $static::httpsredirect_redirect_code \
        Location $redirect_location \
        Connection $static::httpsredirect_connection \
        Cache-Control $static::httpsredirect_cache_control
}
