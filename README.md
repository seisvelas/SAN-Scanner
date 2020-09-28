SAN Scanner is a Burp Suite extension for enumerating associated domains & services via the Subject Alt Names section of SSL certificates. 

| Index |
| ------------- |
| [What is a SAN cert](#what-is-a-san-cert)  |
| [Use for security professionals](#Use-for-security-professionals)  |

## What is a SAN cert

Some webmasters use a single SSL certificate to secure multiple domain names. This is accomplished via the Subject Alternative Name field. For example,
the cert for StackOverflow.com contains dozens of other domain names covered by the same cert:

![StackOverflow SSL Cert](https://github.com/seisvelas/SAN-Scanner/blob/master/Screenshot%20from%202020-09-28%2001-27-24.png)

SAN certs convenience admins because they only have to worry about updating a single certificate for the various domains under their stewardship.

## Use for security professionals

Examining Subject Alt Names is a routine part of enumeration and OSINT. Given a domain, SANs help you find associated domains and services, often hosted in the same
network or server. Recreationally, SAN enumeration is often useful for CTF security games (the 
[Mango](https://medium.com/@tellicolungrevink/hack-the-box-mango-70d906fc8b58) machine on HackTheBox famously hid a needed domain name in an otherwise
inocuous SSL cert).

Aside from the offensive component, SANs often point to out-of-date or no longer extant domains that can be or have been picked up by others. This extension
is useful for reminding webmasters to update such certs.

## Building the extension

TODO. I still need to write this section. Will include instructions for installing deps, building from source, and loading the extension, on Ubuntu (20.04).

## Using the extension

TODO. Should include screenshots of alert output running in Burp against real site.
