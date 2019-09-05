use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use iprange::IpRange;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref REGEX_KEY_MATCH2: Regex = Regex::new(r"(.*):[^/]+(.*)").unwrap();
    static ref REGEX_KEY_MATCH3: Regex = Regex::new(r"(.*)\{[^/]+\}(.*)").unwrap();
}

/// Determines whether `key1` matches the pattern of `key2` (similar to RESTful path).
///
/// `key2` can contain a *. For example, "/foo/bar" matches "/foo/*"
pub fn key_match(key1: &str, key2: &str) -> bool {
    if let Some(i) = key2.find('*') {
        if key1.len() > i {
            key1[0..i] == key2[0..i]
        } else {
            key1 == &key2[0..i]
        }
    } else {
        key1 == key2
    }
}

/// Determine whether `key1` matches the pattern of key2 (similar to RESTful path),
///
/// `key2` can contain a '*' or ':'. For example, "/foo/bar" matches "/foo/*",
/// "/resource1" matches "/:resource".
pub fn key_match2(key1: &str, key2: &str) -> bool {
    let mut key2 = key2.replace("/*", "/.*");

    while key2.contains("/:") {
        key2 = REGEX_KEY_MATCH2.replace_all(&key2, "$1[^/]+$2").to_string();
    }

    while key2.contains("/{") {
        key2 = REGEX_KEY_MATCH3.replace_all(&key2, "$1[^/]+$2").to_string();
    }

    regex_match(key1, &key2)
}

/// Determines whether `key1` matches the pattern of `key2` in regular expression.
pub fn regex_match(key1: &str, key2: &str) -> bool {
    let regex = Regex::new(key2).expect(&format!("invalid regex: {}", key2));
    regex.is_match(key1)
}

/// Determine whether `ip1` matches the pattern of IP address `ip2`.
///
/// `ip2` can be an IP address or a CIDR pattern.
/// For example, "192.168.2.123" matches "192.168.2.0/24"
//
// TODO: ip_match supports only IPv4 addresses.
pub fn ip_match(ip1: &str, ip2: &str) -> bool {
    let ip1: Ipv4Addr = ip1.parse().expect(&format!("invalid ip address: {}", ip1));

    if let Ok(ip2) = ip2.parse() {
        let mut ip_range: IpRange<Ipv4Net> = IpRange::new();
        ip_range.add(ip2);
        return ip_range.contains(&ip1);
    }

    // We failed to parse `ip2` as a network, in this case we try to parse it as an IP address.
    let ip2: Ipv4Addr = ip2.parse().expect(&format!("invalid ip address or network: {}", ip2));
    ip1 == ip2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_match() {
        assert_eq!(key_match("/foo", "/foo"), true);
        assert_eq!(key_match("/foo", "/foo*"), true);
        assert_eq!(key_match("/foo", "/foo/*"), false);
        assert_eq!(key_match("/foo/bar", "/foo"), false);
        assert_eq!(key_match("/foo/bar", "/foo*"), true);
        assert_eq!(key_match("/foo/bar", "/foo/*"), true);
        assert_eq!(key_match("/foobar", "/foo"), false);
        assert_eq!(key_match("/foobar", "/foo*"), true);
        assert_eq!(key_match("/foobar", "/foo/*"), false);
    }

    #[test]
    fn test_key_match2() {
        assert_eq!(key_match2("/foo", "/foo"), true);
        assert_eq!(key_match2("/foo", "/foo*"), true);
        assert_eq!(key_match2("/foo", "/foo/*"), false);
        assert_eq!(key_match2("/foo/bar", "/foo"), true);
        assert_eq!(key_match2("/foo/bar", "/foo*"), true);
        assert_eq!(key_match2("/foo/bar", "/foo/*"), true);
        assert_eq!(key_match2("/foobar", "/foo"), true);
        assert_eq!(key_match2("/foobar", "/foo*"), true);
        assert_eq!(key_match2("/foobar", "/foo/*"), false);

        assert_eq!(key_match2("/", "/:resource"), false);
        assert_eq!(key_match2("/resource1", "/:resource"), true);
        assert_eq!(key_match2("/myid", "/:id/using/:resId"), false);
        assert_eq!(key_match2("/myid/using/myresid", "/:id/using/:resid"), true);

        assert_eq!(key_match2("/proxy/myid", "/proxy/:id/*"), false);
        assert_eq!(key_match2("/proxy/myid/", "/proxy/:id/*"), true);
        assert_eq!(key_match2("/proxy/myid/res", "/proxy/:id/*"), true);
        assert_eq!(key_match2("/proxy/myid/res/res2", "/proxy/:id/*"), true);
        assert_eq!(key_match2("/proxy/myid/res/res2/res3", "/proxy/:id/*"), true);
        assert_eq!(key_match2("/proxy/", "/proxy/:id/*"), false);
    }

    #[test]
    fn test_regex_match() {
        assert_eq!(regex_match("/topic/create", "/topic/create"), true);
        assert_eq!(regex_match("/topic/create/123", "/topic/create"), true);
        assert_eq!(regex_match("/topic/delete", "/topic/create"), false);
        assert_eq!(regex_match("/topic/edit", "/topic/edit/[0-9]+"), false);
        assert_eq!(regex_match("/topic/edit/123", "/topic/edit/[0-9]+"), true);
        assert_eq!(regex_match("/topic/edit/abc", "/topic/edit/[0-9]+"), false);
        assert_eq!(regex_match("/foo/delete/123", "/topic/delete/[0-9]+"), false);
        assert_eq!(regex_match("/topic/delete/0", "/topic/delete/[0-9]+"), true);
        assert_eq!(regex_match("/topic/edit/123s", "/topic/delete/[0-9]+"), false);
    }

    #[test]
    fn test_ip_match() {
        assert_eq!(ip_match("192.168.2.123", "192.168.2.0/24"), true);
        assert_eq!(ip_match("192.168.2.123", "192.168.3.0/24"), false);
        assert_eq!(ip_match("192.168.2.123", "192.168.2.0/16"), true);
        assert_eq!(ip_match("192.168.2.123", "192.168.2.123"), true);
        assert_eq!(ip_match("192.168.2.123", "192.168.2.123/32"), true);
        assert_eq!(ip_match("10.0.0.11", "10.0.0.0/8"), true);
        assert_eq!(ip_match("11.0.0.123", "10.0.0.0/8"), false);
    }
}
