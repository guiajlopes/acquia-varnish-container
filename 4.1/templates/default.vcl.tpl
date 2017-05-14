vcl 4.0;
import std;

# Default backend definition. Points to Apache, normally.
backend default {
    .host = "{{ getenv "VARNISH_BACKEND_HOST" }}";
    .port = "{{ getenv "VARNISH_BACKEND_PORT" "80" }}";
    .first_byte_timeout     = {{ getenv "VARNISH_BACKEND_FIRST_BYTE_TIMEOUT" "300s" }};   # How long to wait before we receive a first byte from our backend?
    .connect_timeout        = {{ getenv "VARNISH_BACKEND_CONNECT_TIMEOUT" "5s" }};     # How long to wait for a backend connection?
    .between_bytes_timeout  = {{ getenv "VARNISH_BACKEND_BETWEEN_BYTES_TIMEOUT" "2s" }};     # How long to wait between bytes received from our backend?
}

# Acquia Template 2016-10-20
# Default Varnish cache policy for Acquia Hosting

# The default backend is specified in another file and should not be declared here.
# All other backends may be declared here.

# Incoming requests: Decide whether to try cache or not
sub vcl_recv {
  # Pipe all websocket requests.
  if (req.http.Upgrade ~ "(?i)websocket") {
    return(pipe);
  }

  if (req.http.X-AH-Redirect) {
    return (synth(751, req.http.X-AH-Redirect));
  }

  # First click free:
  #
  # Support for "first click free" for news articles. Uses the HTTP referer
  # to detect if the browser came from Google, Twitter, Facebook or LinkedIn.
  if (req.http.referer ~
      "(?i)^https?://([^\./]+\.)?(google|twitter|facebook|linkedin|t)\." ||
        req.http.User-Agent ~ "(?i)googlebot|facebookexternalhit|linkedinBot") {
    set req.http.X-UA-FCF = "allow";
  } else {
    set req.http.X-UA-FCF = "deny";
  }

  # Varnish doesn't support Range requests: needs to be piped
  if (req.http.Range) {
    return(pipe);
  }

  # Cache invalidation support:
  #
  #  1. SINGLE URL (404/200):
  #     - method: PURGE
  #     - path: (the path to invalidate)
  #     - header Host: the hostname to clear the path for.
  #     - header X-Acquia-Purge: site ID (no verification)
  #  2. CACHE TAGS (200):
  #     - method: BAN
  #     - path: /tags
  #     - header X-Acquia-Purge: site ID (MUST match X-Acquia-Site value).
  #     - header X-Acquia-Purge-Tags: node:6 theme:garland myentity:145
  #  3. ENTIRE SITE (200):
  #     - method: BAN
  #     - path: /site
  #     - header X-Acquia-Purge: site ID (MUST match X-Acquia-Site value).
  #  4. SINGLE URL + VARIANTS (200):
  #     - method: BAN
  #     - path: (the path to invalidate, e.g.: "path/a?p=1" or "path/*")
  #     - header Host: the hostname to clear the path for.
  #     - header X-Acquia-Purge: site ID (no verification)
  #
  if (req.method == "PURGE") {
    if (!req.http.X-Acquia-Purge) {
      return (synth(405, "Not allowed."));
    }
    return(purge);
  }
  if (req.method == "BAN") {
    if (!req.http.X-Acquia-Purge) {
      return (synth(405, "Permission denied."));
    }
    set req.http.X-Acquia-Purge = std.tolower(req.http.X-Acquia-Purge);
    if (req.url == "/site") {
      ban("obj.http.X-Acquia-Site == " + req.http.X-Acquia-Purge);
      return (synth(200, "Site banned."));
    }
    else if ((req.url == "/tags") && req.http.X-Acquia-Purge-Tags) {
      set req.http.X-Acquia-Purge-Tags = "(^|\s)" + regsuball(std.tolower(req.http.X-Acquia-Purge-Tags), "\ ", "(\\s|$)|(^|\\s)") + "(\s|$)";
      ban("obj.http.X-Acquia-Site == " + req.http.X-Acquia-Purge + " && obj.http.X-Acquia-Purge-Tags ~ " + req.http.X-Acquia-Purge-Tags);
      return (synth(200, "Tags banned."));
    }
    else {
      set req.url = std.tolower(req.url);
      if (req.url ~ "\*") {
        set req.url = regsuball(req.url, "\*", "\.*");
        ban("obj.http.X-Acquia-Host == " + req.http.host + " && obj.http.X-Acquia-Path ~ ^" + req.url + "$");
        return (synth(200, "WILDCARD URL banned."));
      }
      else {
        ban("obj.http.X-Acquia-Host == " + req.http.host + " && obj.http.X-Acquia-Path == " + req.url);
        return (synth(200, "URL banned."));
      }
    }
  }

  # Don't Cache executables or archives
  # This was put in place to ensure these objects are piped rather then passed to the backend.
  # We had a customer who had a 500+MB file *.msi that Varnish was choking on,
  # so we decided to pipe all archives and executables to keep them from choking Varnish.
  if (req.url ~ "\.(msi|exe|dmg|zip|tgz|gz|pkg)") {
    return(pipe);
  }

  # Don't check cache for POSTs and various other HTTP request types
  if (req.method != "GET" && req.method != "HEAD") {
    return(pass);
  }

  # Find out if the request is pinned to a specific device and store it for later.
  if (req.http.Cookie ~ "desktop") {
    set req.http.X-pinned-device = "desktop";
  }
  else if (req.http.Cookie ~ "mobile") {
    set req.http.X-pinned-device = "mobile";
  }
  else if (req.http.Cookie ~ "tablet") {
    set req.http.X-pinned-device = "tablet";
  }

  # Always cache the following file types for all users if not coming from the private file system.
  if (req.url ~ "(?i)/(modules|themes|files|libraries)/.*\.(png|gif|jpeg|jpg|ico|swf|css|js|flv|f4v|mov|mp3|mp4|pdf|doc|ttf|eot|ppt|ogv|woff)(\?[a-z0-9]+)?$" && req.url !~ "/system/files") {
    unset req.http.Cookie;
    # Set header so we know to remove Set-Cookie later on.
    set req.http.X-static-asset = "True";
  }

  # Don't check cache for cron.php
  if (req.url ~ "^/cron.php") {
    return(pass);
  }

  # NOTE: xmlrpc.php requests are not cached because they're POSTs

  # Don't check cache for feedburner or feedvalidator for ise
  if ((req.http.host ~ "^(www\.|web\.)?ise") &&
      (req.http.User-Agent ~ "(?i)feed")) {
       return(pass);
  }

  # Cookie Cache Bypass Drupal module (Pressflow): Don't check cache for
  # any user that just submitted a content form within the past 5 to 10
  # minutes (depending on Drupal's cache_lifetime setting).
  # Persistent login module support: http://drupal.org/node/1306214
  if (req.http.cookie ~ "(NO_CACHE|PERSISTENT_LOGIN_[a-zA-Z0-9]+)") {
    return(pass);
  }

  # This is part of Varnish's default behavior to pass through any request that
  # comes from an http auth'd user.
  if (req.http.Authorization) {
    return(pass);
  }

  # Don't check cache if the Drupal session cookie is set.
  # Pressflow pages don't send this cookie to anon users.
  if (req.http.cookie ~ "(^|;\s*)(S?SESS[a-zA-Z0-9]*)=") {
    return(pass);
  }

  # Enforce no-cookie-vary: Hide the Cookie header prior
  # to vcl_hash, then restore Cookie if we get to vcl_miss.
  # BUG: Varnish is truncates the X-Acquia-Cookie var
  if (req.http.Cookie) {
    set req.http.X-Acquia-Cookie = req.http.cookie;
    unset req.http.Cookie;
  }

  # Pass requests from simpletest to drupal.
  if (req.http.User-Agent ~ "simpletest") {
    return(pipe);
  }

  # Parameter stripping for Google Analytics (unittested). Please note that
  # previous Acquia implementations didn't handle &-sign parameter joins well.
  if (req.url ~ "(\?|&)([gd]clid|gclsrc|cx|ie|cof|hConversionEventId|siteurl|zanpid|origin|os_ehash|utm_[a-z]+|mr:[A-z]+)=") {
    set req.url = regsuball(req.url, "([gd]clid|gclsrc|cx|ie|cof|hConversionEventId|siteurl|zanpid|origin|os_ehash|utm_[a-z]+|mr:[A-z]+)=[A-z0-9%._+-:]*&?", "");
    set req.url = regsub(req.url, "(\??&?)$", "");
  }

  # Default cache check
  return(hash);
}

# Fetch from backend: request is about to be sent to the backend
sub vcl_backend_fetch {
  # Restore the original incoming Cookie
  if (bereq.http.X-Acquia-Cookie) {
    set bereq.http.Cookie = bereq.http.X-Acquia-Cookie;
  }
}

# Alter backend response: request headers have been returned from backend
sub vcl_backend_response {
  if (bereq.http.X-Acquia-Cookie) {
    # Strip the cookies to cache without
    unset bereq.http.cookie;
    unset bereq.http.X-Acquia-Cookie;
  }
}

# piped requests should not support keepalive because
# Varnish won't have chance to process or log the subrequests
sub vcl_pipe {
  if (req.http.upgrade) {
    set bereq.http.upgrade = req.http.upgrade;
  }
  else {
    set req.http.connection = "close";
  }
}

# Backend response: Determine whether to cache each backend response
sub vcl_backend_response {
  # Pipe all requests for files whose Content-Length is >=10,000,000. See
  # comment in vcl_pipe.
  if ( beresp.http.Content-Length ~ "[0-9]{8,}" ) {
    set beresp.do_stream = true;
  }

  # Avoid attempting to gzip an empty response body
  # https://www.varnish-cache.org/trac/ticket/1320
  if (beresp.http.Content-Encoding ~ "gzip" && beresp.http.Content-Length == "0") {
    unset beresp.http.Content-Encoding;
  }

  # Remove the Set-Cookie header from static assets
  # This is just for cleanliness and is also done in vcl_deliver
  if (bereq.http.X-static-asset) {
    unset beresp.http.Set-Cookie;
  }

  # Enforce 15 minute minimum requirements for 301's and 404's. Don't cache
  # responses with statuses >= 302, negative TTLs or HTTP methods other
  # than GET or HEAD (the latter is like a GET, without body payload).
  if ((beresp.status == 301) || (beresp.status == 404)) {
    if (!beresp.http.X-Acquia-No-301-404-Caching-Enforcement) {
      if (beresp.ttl < 15m) {
        set beresp.http.Cache-Control = "max-age=900, public";
        set beresp.ttl = 15m;
      }
    }
  }
  else if (beresp.status >= 302 || !(beresp.ttl > 0s)
    || !((bereq.method == "GET") || bereq.method == "HEAD")) {
    call ah_pass;
  }

  # First click free:
  #
  # OPT-IN cache varying for the X-UA-FCF header. The backend must set the
  # response header X-UA-FCF-Enabled to any arbitrary value and the Vary header
  # will be set or altered.
  if (bereq.http.X-UA-FCF && beresp.http.X-UA-FCF-Enabled) {
    set beresp.http.X-UA-FCF = bereq.http.X-UA-FCF;
    if (!beresp.http.Vary) {
      set beresp.http.Vary = "X-UA-FCF";
    } elsif (beresp.http.Vary !~ "(?i)X-UA-FCF") {
      set beresp.http.Vary = beresp.http.Vary + ",X-UA-FCF";
    }
  }

  # Cache invalidation support:
  #
  # Create VCL internal headers that are used in the BAN's we issue. Technically
  # it is possible to do it without these, but then you must reference req.*
  # variables inside the BAN. That's called "BAN lurker unfriendly" and has the
  # consequence that invalidation only happens at the edge and not in the much
  # more efficient separate BAN lurker process.
  set beresp.http.X-Acquia-Host = std.tolower(bereq.http.host);
  set beresp.http.X-Acquia-Path = std.tolower(bereq.url);
  set beresp.http.X-Acquia-Site = std.tolower(beresp.http.X-Acquia-Site);
  set beresp.http.X-Acquia-Purge-Tags = std.tolower(beresp.http.X-Acquia-Purge-Tags);

  # Respect explicit no-cache headers
  if (beresp.http.Pragma ~ "no-cache" ||
      beresp.http.Cache-Control ~ "no-cache" ||
      beresp.http.Cache-Control ~ "private") {
    call ah_pass;
  }

  # Don't cache cron.php
  if (bereq.url ~ "^/cron.php") {
    call ah_pass;
  }

  # NOTE: xmlrpc.php requests are not cached because they're POSTs

  # Don't cache if Drupal session cookie is set
  # Note: Pressflow doesn't send SESS cookies to anon users
  if (beresp.http.Set-Cookie ~ "SESS") {
    call ah_pass;
  }

  # Grace: Avoid thundering herd when an object expires by serving
  # expired stale object during the next N seconds while one request
  # is made to the backend for that object.
  set beresp.grace = 2m;

  # Cache anything else. Returning nothing here would fall-through
  # to Varnish's default cache store policies.
  return(deliver);
}

# Deliver the response to the client
sub vcl_deliver {
  # Redirect the request if the AH-Mobile-Redirect or AH-Tablet-Redirect header or X-AH-Desktop-Redirect
  # is set and the devices is a mobile, tablet or desktop.
  if (resp.http.X-AH-Mobile-Redirect || resp.http.X-AH-Tablet-Redirect || resp.http.X-AH-Desktop-Redirect && !resp.http.X-AH-Mobile-Redirect) {

    # Make sure remap header is added to req if needed
    if (resp.http.X-AH-Redirect-No-Remap) {
      set req.http.X-AH-Redirect-No-Remap = resp.http.X-AH-Redirect-No-Remap;
    }

    if ( resp.http.X-AH-Mobile-Redirect && req.http.X-UA-Device ~ "mobile" && req.http.X-pinned-device != "mobile" ) {
      if (resp.http.X-AH-Mobile-Redirect !~ "(?i)^https?://") {
        set resp.http.X-AH-Mobile-Redirect = "http://" + resp.http.X-AH-Mobile-Redirect;
      }
      set req.http.X-AH-Redirect = resp.http.X-AH-Mobile-Redirect;
      call ah_device_redirect_check;
    }
    else if ( resp.http.X-AH-Tablet-Redirect && req.http.X-UA-Device ~ "tablet" && req.http.X-pinned-device != "tablet" ) {
      if (resp.http.X-AH-Tablet-Redirect !~ "(?i)^https?://") {
        set resp.http.X-AH-Tablet-Redirect = "http://" + resp.http.X-AH-Tablet-Redirect;
      }
      set req.http.X-AH-Redirect = resp.http.X-AH-Tablet-Redirect;
      call ah_device_redirect_check;
    }
    else if ( resp.http.X-AH-Desktop-Redirect && req.http.X-UA-Device ~ "pc" && req.http.X-pinned-device != "desktop" ) {
      if (resp.http.X-AH-Desktop-Redirect !~ "(?i)^https?://") {
        set resp.http.X-AH-Desktop-Redirect = "http://" + resp.http.X-AH-Desktop-Redirect;
      }
      set req.http.X-AH-Redirect = resp.http.X-AH-Desktop-Redirect;
      call ah_device_redirect_check;
    }
  }

  # Unset the X-AH redirect headers if they exist here
  unset resp.http.X-AH-Mobile-Redirect;
  unset resp.http.X-AH-Tablet-Redirect;
  unset resp.http.X-AH-Desktop-Redirect;
  unset resp.http.X-AH-Redirect-No-Remap;

  # Add an X-Cache diagnostic header
  if (obj.hits > 0) {
    set resp.http.X-Cache = "HIT";
    set resp.http.X-Cache-Hits = obj.hits;
    # Don't echo cached Set-Cookie headers
    unset resp.http.Set-Cookie;
  } else {
    set resp.http.X-Cache = "MISS";
  }

  # Strip the age header for Akamai requests
  if (req.http.Via ~ "akamai") {
    set resp.http.X-Age = resp.http.Age;
    unset resp.http.Age;
  }

  # Remove the Set-Cookie header from static assets
  if (req.http.X-static-asset) {
    unset resp.http.Set-Cookie;
  }

  # Cache invalidation support:
  #
  # Strip internal headers initially copied over in vcl_fetch. To aid support's
  # often tough caching investigations, allow header leaking for debugging.
  if (!req.http.X-Acquia-Purge-Debug) {
    unset resp.http.X-Acquia-Host;
    unset resp.http.X-Acquia-Path;
    unset resp.http.X-Acquia-Site;
    unset resp.http.X-Acquia-Purge-Tags;
  }

  # Force Safari to always check the server as it doesn't respect Vary: cookie.
  # See https://bugs.webkit.org/show_bug.cgi?id=71509
  # Static assets may be cached however as we already forcefully remove the
  # cookies for them.
  if (req.http.user-agent ~ "Safari" && !req.http.user-agent ~ "Chrome" && !req.http.X-static-asset) {
    set resp.http.cache-control = "max-age: 0";
  }
  # ELB health checks respect HTTP keep-alives, but require the connection to
  # remain open for 60 seconds. Varnish's default keep-alive idle timeout is
  # 5 seconds, which also happens to be the minimum ELB health check interval.
  # The result is a race condition in which Varnish can close an ELB health
  # check connection just before a health check arrives, causing that check to
  # fail. Solve the problem by not allowing HTTP keep-alive for ELB checks.
  if (req.http.user-agent ~ "ELB-HealthChecker") {
    set resp.http.Connection = "close";
  }
  return(deliver);
}


# Backend down: Error page returned when all backend servers are down
sub vcl_synth {
  # mobile browsers redirect
  if (resp.status == 750) {
    set resp.http.Location = resp.reason + req.url;
    set resp.status = 302;
    set resp.reason = "Found";
    return(deliver);
  }

  # user defined device redirect
  if (resp.status == 751) {
    if (req.http.X-AH-Redirect-No-Remap) {
      set resp.http.Location = resp.reason;
    }
    else {
      set resp.http.Location = resp.reason + req.url;
    }
    set resp.status = 302;
    set resp.reason = "Found";
    return(deliver);
  }

  set resp.http.Content-Type = "text/html; charset=utf-8";
  set resp.http.Retry-After = "5";
  synthetic( {"<!DOCTYPE html>
<html>
  <head>
    <title>"} + resp.status + " " + resp.reason + {"</title>
  </head>
  <body>
    <h1>This server is experiencing technical problems. Please
try again in a few moments. Thanks for your continued patience, and
we're sorry for any inconvenience this may cause.</h1>
    <p>Error "} + resp.status + " " + resp.reason + {"</p>
    <p>"} + resp.reason + {"</p>
    <h3>Guru Meditation:</h3>
    <p>XID: "} + req.xid + {"</p>
    <hr>
    <p>Varnish cache server</p>
  </body>
</html>
"} );
  return (deliver);
}

# Backend down: Error page returned when all backend servers are down
sub vcl_backend_error {

  # Default Varnish error (Nginx didn't reply)
  set beresp.http.Content-Type = "text/html; charset=utf-8";

  synthetic( {"<!DOCTYPE html>
  <html>
    <head>
      <title>"} + beresp.status + " " + beresp.reason + {"</title>
    </head>
    <body>
    <h1>This server is experiencing technical problems. Please
try again in a few moments. Thanks for your continued patience, and
we're sorry for any inconvenience this may cause.</h1>
    <p>Error "} + beresp.status + " " + beresp.reason + {"</p>
    <p>"} + beresp.reason + {"</p>
      <p>XID: "} + bereq.xid + {"</p>
    </body>
   </html>
   "} );
  return(deliver);
}

# Separate pass subroutine to shorten the lifetime of beresp.ttl
# This will reduce the amount of "Cache Hits for Pass" for objects
sub ah_pass {
  set beresp.uncacheable = true;
  set beresp.ttl = 10s;
  return(deliver);
}

# Test if a device redirect is attempting to redirect to the same path as the
# request came from. This should stop the state machine restart and remove the
# redirect from the headers.
sub ah_device_redirect_check {
  if (req.http.X-AH-Redirect-No-Remap) {
    if (req.http.X-Forwarded-Proto) {
      if (req.http.X-AH-Redirect != req.http.X-Forwarded-Proto + "://" + req.http.host + req.url) {
        return(restart);
      }
    }
    else {
      if (req.http.X-AH-Redirect != "http://" + req.http.host + req.url) {
        return(restart);
      }
    }
  }
  else {
    if (req.http.X-Forwarded-Proto) {
      if (req.http.X-AH-Redirect != req.http.X-Forwarded-Proto + "://" + req.http.host) {
        return(restart);
      }
    }
    else {
      if (req.http.X-AH-Redirect != "http://" + req.http.host) {
        return(restart);
      }
    }
  }
  # Redirection fell through so we will remove the redirect header.
  unset req.http.X-AH-Redirect;
}
