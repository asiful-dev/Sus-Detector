import ssl
import socket
import datetime
import sys
from urllib.parse import urlparse
import OpenSSL.crypto
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_certificate_info(hostname, port=443, timeout=10):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                return der_cert, cert_dict, ssock.version(), ssock.cipher()
    except Exception as e:
        print(f"Error connecting to {hostname}:{port} - {str(e)}")
        return None, None, None, None

def parse_certificate_details(der_cert):
    if not der_cert:
        return None
    try:
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        return cert
    except Exception as e:
        print(f"Error parsing certificate: {str(e)}")
        return None

def display_certificate_info(hostname, port=443):
    print("="*60)
    print(f"SSL/TLS Certificate Information for {hostname}:{port}")
    print("="*60)
    der_cert, cert_dict, tls_version, cipher_info = get_certificate_info(hostname, port)
    if not der_cert or not cert_dict:
        print("Failed to retrieve certificate information")
        return
    cert_obj = parse_certificate_details(der_cert)
    print("\n\ud83d\udccb BASIC INFORMATION")
    print("-" * 30)
    print(f"Hostname: {hostname}")
    print(f"Port: {port}")
    print(f"TLS Version: {tls_version}")
    if cipher_info:
        print(f"Cipher Suite: {cipher_info[0]}")
        print(f"TLS Version: {cipher_info[1]}")
        print(f"Key Exchange: {cipher_info[2]} bits")
    print("\n\ud83c\udfe2 CERTIFICATE DETAILS")
    print("-" * 30)
    if 'subject' in cert_dict:
        subject = dict(x[0] for x in cert_dict['subject'])
        print(f"Subject Common Name (CN): {subject.get('commonName', 'N/A')}")
        print(f"Subject Organization (O): {subject.get('organizationName', 'N/A')}")
        print(f"Subject Organizational Unit (OU): {subject.get('organizationalUnitName', 'N/A')}")
        print(f"Subject Country (C): {subject.get('countryName', 'N/A')}")
        print(f"Subject State/Province (ST): {subject.get('stateOrProvinceName', 'N/A')}")
        print(f"Subject Locality (L): {subject.get('localityName', 'N/A')}")
    if 'issuer' in cert_dict:
        issuer = dict(x[0] for x in cert_dict['issuer'])
        print(f"\nIssuer Common Name (CN): {issuer.get('commonName', 'N/A')}")
        print(f"Issuer Organization (O): {issuer.get('organizationName', 'N/A')}")
        print(f"Issuer Country (C): {issuer.get('countryName', 'N/A')}")
    print("\n\ud83d\uddd5 VALIDITY INFORMATION")
    print("-" * 30)
    if 'notBefore' in cert_dict and 'notAfter' in cert_dict:
        not_before = datetime.datetime.strptime(cert_dict['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.datetime.strptime(cert_dict['notAfter'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.datetime.now()
        print(f"Valid From: {not_before}")
        print(f"Valid Until: {not_after}")
        print(f"Days Until Expiry: {(not_after - now).days}")
        if now < not_before:
            print("Status: \u26a0\ufe0f  Certificate not yet valid")
        elif now > not_after:
            print("Status: \u274c Certificate expired")
        else:
            print("Status: \u2705 Certificate valid")
    if 'serialNumber' in cert_dict:
        print(f"Serial Number: {cert_dict['serialNumber']}")
    if 'version' in cert_dict:
        print(f"Version: {cert_dict['version']}")
    if 'subjectAltName' in cert_dict:
        print(f"\n\ud83c\udf10 SUBJECT ALTERNATIVE NAMES")
        print("-" * 30)
        for san_type, san_value in cert_dict['subjectAltName']:
            print(f"{san_type}: {san_value}")
    if cert_obj:
        print("\n\ud83d\udd10 CRYPTOGRAPHIC DETAILS")
        print("-" * 30)
        public_key = cert_obj.public_key()
        print(f"Public Key Algorithm: {cert_obj.public_key_algorithm_oid._name}")
        if hasattr(public_key, 'key_size'):
            print(f"Public Key Size: {public_key.key_size} bits")
        print(f"Signature Algorithm: {cert_obj.signature_algorithm_oid._name}")
        print(f"\n\ud83d\udcdc CERTIFICATE EXTENSIONS")
        print("-" * 30)
        try:
            for ext in cert_obj.extensions:
                print(f"Extension: {ext.oid._name}")
                print(f"Critical: {ext.critical}")
                if isinstance(ext.value, x509.KeyUsage):
                    usages = []
                    if ext.value.digital_signature: usages.append("Digital Signature")
                    if ext.value.key_encipherment: usages.append("Key Encipherment")
                    if ext.value.data_encipherment: usages.append("Data Encipherment")
                    if ext.value.key_agreement: usages.append("Key Agreement")
                    if ext.value.key_cert_sign: usages.append("Key Cert Sign")
                    if ext.value.crl_sign: usages.append("CRL Sign")
                    print(f"Key Usages: {', '.join(usages)}")
                elif isinstance(ext.value, x509.ExtendedKeyUsage):
                    usages = [usage._name for usage in ext.value]
                    print(f"Extended Key Usages: {', '.join(usages)}")
                print()
        except Exception as e:
            print(f"Error reading extensions: {e}")

def check_ssl_labs_rating(hostname):
    try:
        print("\n\ud83d\udd0d SSL LABS RATING")
        print("-" * 30)
        print("Note: This would require SSL Labs API integration")
        print("You can manually check at: https://www.ssllabs.com/ssltest/")
    except:
        pass

def main():
    if len(sys.argv) != 2:
        print("Usage: python ssl_checker.py <hostname>")
        print("Example: python ssl_checker.py google.com")
        sys.exit(1)
    hostname = sys.argv[1]
    if hostname.startswith('http://') or hostname.startswith('https://'):
        parsed_url = urlparse(hostname)
        hostname = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    else:
        port = 443
    try:
        display_certificate_info(hostname, port)
        check_ssl_labs_rating(hostname)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("SSL/TLS Certificate Checker")
        print("="*30)
        hostname = input("Enter hostname to check: ").strip()
        if hostname:
            if hostname.startswith('http://') or hostname.startswith('https://'):
                parsed_url = urlparse(hostname)
                hostname = parsed_url.hostname
                port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            else:
                port = 443
            display_certificate_info(hostname, port)
            check_ssl_labs_rating(hostname)
    else:
        main()
