# TLS Cert Checker

A simple program that helps in the management of TLS certificates for a group of hosts.

# Building

This program is written in Rust. If you do not have a rust environment visit the [rustup](https://rustup.rs/) site and install the rust language tooling.

Once done, use cargo to build the program:

``` bash
$ cargo build --release
```

# Usage

Provide the program a list of host names in a file and what you would like the output CSV file to be called.
It will run through the host names and provide basic certificate information such as issuer, subject and expiry dates. For example:

``` bash
$ ./target/release/tls_cert_checker -i hostnames_example.txt -o output.csv
```

The program is silent unless there is an error, in which case Errors will be shown. For example;

``` bash
$ ./target/release/tls_cert_checker -i bad.txt -o output.csv
[2022-09-26T01:11:13Z ERROR tls_cert_checker] Error opening input file: No such file or directory (os error 2)

```

If you would like to get full debug output set the debug level before running the command. For example:

``` bash
$ RUST_LOG=warn ./target/release/tls_cert_checker -i hostnames_example.txt -o output.csv
[2022-09-26T01:17:09Z WARN  tls_cert_checker] potentially malformed hostname: 

```

Valid log levels are; trace, debug, info, warn, error

# Example Output

Output is provided in CSV for ease of use. Dates are RFC2822 formatted.

| hostname             | issuer                                           | subject                 | valid_not_before                | valid_not_after                 |
|----------------------|--------------------------------------------------|-------------------------|---------------------------------|---------------------------------|
| hyperviewhq.com      | C=US, O=Let's Encrypt, CN=R3                     | CN=tls.automattic.com   | Thu, 15 Sep 2022 00:15:09 +0000 | Wed, 14 Dec 2022 00:15:08 +0000 |
| docs.hyperviewhq.com | C=US, O=Let's Encrypt, CN=R3                     | CN=docs.hyperviewhq.com | Tue, 30 Aug 2022 18:48:04 +0000 | Mon, 28 Nov 2022 18:48:03 +0000 |
| google.com           | C=US, O=Google Trust Services LLC, CN=GTS CA 1C3 | CN=*.google.com         | Mon, 05 Sep 2022 08:17:24 +0000 | Mon, 28 Nov 2022 08:17:23 +0000 |

