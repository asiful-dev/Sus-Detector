from flask import Flask, request, render_template
import ssl
import socket
import datetime
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

def get_certificate_info(hostname, port=443, timeout=10):
    """
    Retrieve SSL certificate information from a website
    """
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
    """
    Parse certificate using cryptography library for detailed information
    """
    if not der_cert:
        return None
    try:
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        return cert
    except Exception as e:
        print(f"Error parsing certificate: {str(e)}")
        return None

def format_certificate_data(hostname, port, der_cert, cert_dict, tls_version, cipher_info, cert_obj):
    """
    Format certificate data for template display
    """
    cert_info = {}
    
    # Basic information
    cert_info['hostname'] = hostname
    cert_info['port'] = port
    cert_info['tls_version'] = tls_version
    cert_info['has_ssl'] = True
    
    if cipher_info:
        cert_info['cipher_suite'] = cipher_info[0]
        cert_info['tls_protocol'] = cipher_info[1]
        cert_info['key_exchange_bits'] = cipher_info[2] if len(cipher_info) > 2 else 'N/A'
    
    # Subject information
    if 'subject' in cert_dict:
        subject = dict(x[0] for x in cert_dict['subject'])
        cert_info['subject'] = {
            'common_name': subject.get('commonName', 'N/A'),
            'organization': subject.get('organizationName', 'N/A'),
            'organizational_unit': subject.get('organizationalUnitName', 'N/A'),
            'country': subject.get('countryName', 'N/A'),
            'state': subject.get('stateOrProvinceName', 'N/A'),
            'locality': subject.get('localityName', 'N/A')
        }
    
    # Issuer information
    if 'issuer' in cert_dict:
        issuer = dict(x[0] for x in cert_dict['issuer'])
        cert_info['issuer'] = {
            'common_name': issuer.get('commonName', 'N/A'),
            'organization': issuer.get('organizationName', 'N/A'),
            'country': issuer.get('countryName', 'N/A')
        }
    
    # Validity information
    if 'notBefore' in cert_dict and 'notAfter' in cert_dict:
        not_before = datetime.datetime.strptime(cert_dict['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.datetime.strptime(cert_dict['notAfter'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.datetime.now()
        
        cert_info['validity'] = {
            'not_before': not_before.strftime('%Y-%m-%d %H:%M:%S'),
            'not_after': not_after.strftime('%Y-%m-%d %H:%M:%S'),
            'days_until_expiry': (not_after - now).days,
            'is_valid': not_before <= now <= not_after,
            'is_expired': now > not_after,
            'not_yet_valid': now < not_before
        }
    
    # Additional details
    cert_info['serial_number'] = cert_dict.get('serialNumber', 'N/A')
    cert_info['version'] = cert_dict.get('version', 'N/A')
    
    # Subject Alternative Names
    if 'subjectAltName' in cert_dict:
        cert_info['subject_alt_names'] = [{'type': san[0], 'value': san[1]} for san in cert_dict['subjectAltName']]
    else:
        cert_info['subject_alt_names'] = []
    
    # Cryptographic details from cert object
    if cert_obj:
        public_key = cert_obj.public_key()
        cert_info['crypto'] = {
            'public_key_algorithm': cert_obj.public_key_algorithm_oid._name,
            'signature_algorithm': cert_obj.signature_algorithm_oid._name,
            'public_key_size': getattr(public_key, 'key_size', 'N/A')
        }
        
        # Extensions
        extensions = []
        try:
            for ext in cert_obj.extensions:
                ext_info = {
                    'name': ext.oid._name,
                    'critical': ext.critical
                }
                
                if isinstance(ext.value, x509.KeyUsage):
                    usages = []
                    if ext.value.digital_signature: usages.append("Digital Signature")
                    if ext.value.key_encipherment: usages.append("Key Encipherment")
                    if ext.value.data_encipherment: usages.append("Data Encipherment")
                    if ext.value.key_agreement: usages.append("Key Agreement")
                    if ext.value.key_cert_sign: usages.append("Key Cert Sign")
                    if ext.value.crl_sign: usages.append("CRL Sign")
                    ext_info['key_usages'] = usages
                
                elif isinstance(ext.value, x509.ExtendedKeyUsage):
                    ext_info['extended_key_usages'] = [usage._name for usage in ext.value]
                
                extensions.append(ext_info)
        except Exception as e:
            print(f"Error reading extensions: {e}")
        
        cert_info['extensions'] = extensions
    
    return cert_info

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/result', methods=['POST'])
def predict():
    url_input = request.form["name"]
    
    # Parse URL to get hostname and determine if HTTPS
    if url_input.startswith('http://') or url_input.startswith('https://'):
        parsed_url = urlparse(url_input)
        hostname = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        has_https = parsed_url.scheme == 'https'
    else:
        # If no protocol specified, assume HTTPS and try to connect
        hostname = url_input
        port = 443
        has_https = True
        url_input = f"https://{hostname}"  # Normalize URL for display
    
    if not hostname:
        return render_template("index.html", 
                             error="Invalid URL provided. Please enter a valid website URL.")
    
    # For HTTP URLs, show limited information
    if not has_https:
        result = {
            'url': url_input,
            'hostname': hostname,
            'port': port,
            'has_ssl': False,
            'status': 'INSECURE',
            'message': 'This website does not use SSL/TLS encryption',
            'prediction_score': '0',
            'has_https_scheme': False
        }
        return render_template("index.html", name=result)
    
    # Get certificate information for HTTPS URLs
    der_cert, cert_dict, tls_version, cipher_info = get_certificate_info(hostname, port)
    
    if not der_cert or not cert_dict:
        result = {
            'url': url_input,
            'hostname': hostname,
            'port': port,
            'has_ssl': False,
            'status': 'ERROR',
            'message': 'Unable to retrieve SSL certificate information',
            'prediction_score': '0',
            'has_https_scheme': has_https,
            'error': 'Failed to connect or retrieve certificate'
        }
        return render_template("index.html", name=result)
    
    # Parse certificate for detailed information
    cert_obj = parse_certificate_details(der_cert)
    
    # Format certificate data
    cert_info = format_certificate_data(hostname, port, der_cert, cert_dict, tls_version, cipher_info, cert_obj)
    
    # Determine certificate status
    is_valid = cert_info.get('validity', {}).get('is_valid', False)
    is_expired = cert_info.get('validity', {}).get('is_expired', False)
    
    if is_expired:
        status = 'EXPIRED'
        message = 'SSL Certificate has expired'
        prediction_score = '0'
    elif is_valid:
        status = 'SECURE'
        message = 'SSL Certificate is valid and secure'
        prediction_score = '1'
    else:
        status = 'INVALID'
        message = 'SSL Certificate is not yet valid'
        prediction_score = '0'
    
    result = {
        'url': url_input,
        'hostname': hostname,
        'port': port,
        'has_ssl': True,
        'status': status,
        'message': message,
        'prediction_score': prediction_score,
        'has_https_scheme': has_https
    }
    
    return render_template("index.html", name=result, cert_info=cert_info)

if __name__ == "__main__":
    app.run(debug=True)