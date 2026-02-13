"""
BREACH.AI - Helper Utilities

Common utility functions used throughout the application.
"""

import hashlib
import re
import uuid
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse


def generate_id(prefix: str = "") -> str:
    """Generate a unique ID."""
    uid = uuid.uuid4().hex[:8]
    if prefix:
        return f"{prefix}-{uid}"
    return uid


def extract_domain(url: str) -> str:
    """Extract the domain from a URL."""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split('/')[0]


def extract_base_url(url: str) -> str:
    """Extract the base URL (scheme + netloc)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_url(url: str, base_url: Optional[str] = None) -> str:
    """
    Normalize a URL.

    - Adds scheme if missing
    - Removes trailing slash
    - Resolves relative URLs against base_url
    """
    url = url.strip()

    # Handle relative URLs
    if base_url and not url.startswith(('http://', 'https://', '//')):
        url = urljoin(base_url, url)

    # Add scheme if missing
    if url.startswith('//'):
        url = 'https:' + url
    elif not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Parse and normalize
    parsed = urlparse(url)

    # Remove default ports
    netloc = parsed.netloc
    if netloc.endswith(':443') and parsed.scheme == 'https':
        netloc = netloc[:-4]
    elif netloc.endswith(':80') and parsed.scheme == 'http':
        netloc = netloc[:-3]

    # Normalize path
    path = parsed.path or '/'
    if path != '/' and path.endswith('/'):
        path = path[:-1]

    return urlunparse((
        parsed.scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        ''  # Remove fragment
    ))


def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin."""
    p1 = urlparse(url1)
    p2 = urlparse(url2)
    return (p1.scheme == p2.scheme and
            p1.netloc.lower() == p2.netloc.lower())


def is_subdomain_of(subdomain: str, domain: str) -> bool:
    """Check if subdomain is a subdomain of domain."""
    subdomain = subdomain.lower().rstrip('.')
    domain = domain.lower().rstrip('.')

    if subdomain == domain:
        return True

    return subdomain.endswith('.' + domain)


def get_url_params(url: str) -> dict:
    """Extract query parameters from URL."""
    parsed = urlparse(url)
    return {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}


def add_url_params(url: str, params: dict) -> str:
    """Add query parameters to a URL."""
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query)

    # Update with new params
    for key, value in params.items():
        existing_params[key] = [value] if not isinstance(value, list) else value

    new_query = urlencode(existing_params, doseq=True)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def safe_filename(name: str, max_length: int = 100) -> str:
    """Convert a string to a safe filename."""
    # Remove or replace unsafe characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', name)
    safe = re.sub(r'\s+', '_', safe)
    safe = re.sub(r'_+', '_', safe)
    safe = safe.strip('_.')

    if len(safe) > max_length:
        safe = safe[:max_length]

    return safe or 'unnamed'


def hash_string(s: str) -> str:
    """Generate a short hash of a string."""
    return hashlib.md5(s.encode()).hexdigest()[:12]


def truncate(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate a string to max_length."""
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def extract_emails(text: str) -> list[str]:
    """Extract email addresses from text."""
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text)))


def extract_urls(text: str) -> list[str]:
    """Extract URLs from text."""
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return list(set(re.findall(pattern, text)))


def extract_paths(text: str) -> list[str]:
    """Extract file paths from text."""
    patterns = [
        r'/[a-zA-Z0-9_\-./]+\.[a-zA-Z]{2,4}',  # Unix paths with extension
        r'/[a-zA-Z0-9_\-./]+',  # Unix paths
    ]
    paths = []
    for pattern in patterns:
        paths.extend(re.findall(pattern, text))
    return list(set(paths))


def extract_ips(text: str) -> list[str]:
    """Extract IP addresses from text."""
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(pattern, text)
    # Validate IP addresses
    valid_ips = []
    for ip in ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            valid_ips.append(ip)
    return list(set(valid_ips))


def detect_technology(headers: dict, body: str) -> list[str]:
    """Detect technologies from headers and response body."""
    technologies = []

    # Header-based detection
    server = headers.get('server', '').lower()
    powered_by = headers.get('x-powered-by', '').lower()

    if 'nginx' in server:
        technologies.append('nginx')
    if 'apache' in server:
        technologies.append('apache')
    if 'iis' in server:
        technologies.append('iis')
    if 'cloudflare' in server:
        technologies.append('cloudflare')

    if 'php' in powered_by:
        technologies.append('php')
    if 'asp.net' in powered_by:
        technologies.append('asp.net')
    if 'express' in powered_by:
        technologies.append('express')

    # Body-based detection
    body_lower = body.lower()

    if 'wp-content' in body_lower or 'wordpress' in body_lower:
        technologies.append('wordpress')
    if 'drupal' in body_lower:
        technologies.append('drupal')
    if 'joomla' in body_lower:
        technologies.append('joomla')
    if 'react' in body_lower or '_next' in body_lower:
        technologies.append('react')
    if 'vue' in body_lower:
        technologies.append('vue')
    if 'angular' in body_lower:
        technologies.append('angular')
    if 'jquery' in body_lower:
        technologies.append('jquery')
    if 'bootstrap' in body_lower:
        technologies.append('bootstrap')

    return list(set(technologies))


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def format_size(bytes_count: int) -> str:
    """Format bytes into human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.1f} TB"


def timestamp() -> str:
    """Get current timestamp string."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def is_internal_ip(ip: str) -> bool:
    """Check if an IP address is internal/private."""
    parts = [int(p) for p in ip.split('.')]

    # 10.0.0.0 - 10.255.255.255
    if parts[0] == 10:
        return True

    # 172.16.0.0 - 172.31.255.255
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True

    # 192.168.0.0 - 192.168.255.255
    if parts[0] == 192 and parts[1] == 168:
        return True

    # Loopback
    if parts[0] == 127:
        return True

    return False


def clean_html(html: str) -> str:
    """Remove HTML tags from text."""
    clean = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r'<style[^>]*>.*?</style>', '', clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r'<[^>]+>', '', clean)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()


def extract_forms(html: str) -> list[dict]:
    """Extract forms from HTML."""
    forms = []
    form_pattern = r'<form[^>]*>(.*?)</form>'
    input_pattern = r'<input[^>]*>'
    attr_pattern = r'(\w+)=["\']([^"\']*)["\']'

    for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
        form_html = form_match.group(0)
        form_content = form_match.group(1)

        # Extract form attributes
        form_attrs = dict(re.findall(attr_pattern, form_html.split('>')[0]))

        form_data = {
            'action': form_attrs.get('action', ''),
            'method': form_attrs.get('method', 'GET').upper(),
            'inputs': []
        }

        # Extract input fields
        for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
            input_html = input_match.group(0)
            input_attrs = dict(re.findall(attr_pattern, input_html))
            form_data['inputs'].append({
                'name': input_attrs.get('name', ''),
                'type': input_attrs.get('type', 'text'),
                'value': input_attrs.get('value', ''),
            })

        forms.append(form_data)

    return forms


def extract_links(html: str, base_url: str = "") -> list[str]:
    """Extract links from HTML."""
    pattern = r'href=["\']([^"\']+)["\']'
    links = re.findall(pattern, html, re.IGNORECASE)

    # Normalize links
    normalized = []
    for link in links:
        if link.startswith('#') or link.startswith('javascript:') or link.startswith('mailto:'):
            continue
        try:
            normalized.append(normalize_url(link, base_url))
        except Exception:
            pass

    return list(set(normalized))


def extract_scripts(html: str, base_url: str = "") -> list[str]:
    """Extract script URLs from HTML."""
    pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
    scripts = re.findall(pattern, html, re.IGNORECASE)

    normalized = []
    for script in scripts:
        try:
            normalized.append(normalize_url(script, base_url))
        except Exception:
            pass

    return list(set(normalized))
