# do some import
import msal
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509


# Define Environmental
client_id = "8f9e2fdf-5caa-4fc4-9acb-5fc5838abf55"
client_cert_path = """C:\Users\eugenewang\Downloads\swarm-kv-eugene-EpicEdgeMsitPrincipalOneCert-20230831.pem"""
tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47"
scope = "499b84ac-1321-427f-aa17-267ca6975798/.default" # Devops Scope API


## return a cert { private_key, thumbprint, public_certificate}
def load_pem(pem_file_path): 
    with open(pem_file_path, 'r') as f:
        pem_data = f.read()

        # Split the PEM data into private key and certificate
        private_key_marker = "-----BEGIN PRIVATE KEY-----"
        end_private_key_marker = "-----END PRIVATE KEY-----"
        certificate_marker = "-----BEGIN CERTIFICATE-----"
        end_certificate_marker = "-----END CERTIFICATE-----"

        # Find the positions of the markers for the private key and certificate
        private_key_start = pem_data.index(private_key_marker)
        private_key_end = pem_data.index(end_private_key_marker) + len(end_private_key_marker)
        certificate_start = pem_data.index(certificate_marker)
        certificate_end = pem_data.index(end_certificate_marker) + len(end_certificate_marker)

        # Extract the private key and certificate based on the positions of these markers
        private_key_pem = pem_data[private_key_start:private_key_end]
        certificate_pem = pem_data[certificate_start:certificate_end]

        # Output the private key and certificate
        # print("Private Key:")
        # print(private_key_pem)
        # print("\nCertificate:")
        # print(certificate_pem)
        get_thumbprint(private_key_pem)
        cert_thumbprint = get_cert_thumbprint(certificate_pem)
        return {"private_key": private_key_pem, 
                "thumbprint": cert_thumbprint, 
                "public_certificate": certificate_pem,
                "passphrase": ""
                }


def get_thumbprint(private_key_pem):

    # Deserialize the PEM private key to a cryptography object
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )

    # Serialize the private key to its DER format
    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Calculate the SHA-256 hash of the DER private key
    thumbprint = hashlib.sha256(private_key_der).digest()

    # Convert the binary hash to a colon-separated hexadecimal string
    thumbprint_hex = "".join([format(b, "02x") for b in bytearray(thumbprint)]).upper()
    print("Thumbprint (SHA-256):");
    print("Private Key Thumbprint (SHA-256):" + thumbprint_hex)
    return thumbprint_hex
    

def get_cert_thumbprint(certificate_pem):
    # Sample PEM certificate as a string. Replace this with your actual certificate.
    # Deserialize the PEM certificate to a cryptography object
    certificate = x509.load_pem_x509_certificate(
        certificate_pem.encode(),
        default_backend()
    )

    # Serialize the certificate to its DER format
    certificate_der = certificate.public_bytes(
        encoding=serialization.Encoding.DER
    )

    # Calculate the SHA-1 hash of the DER certificate
    thumbprint = hashlib.sha1(certificate_der).digest()

    # Convert the binary hash to a colon-separated hexadecimal string
    thumbprint_hex = "".join([format(b, "02x") for b in bytearray(thumbprint)]).upper()
    print("Certificate Thumbprint (SHA-1):" + thumbprint_hex)
    return thumbprint_hex


def get_token():
    cert = load_pem(client_cert_path)

    app = msal.ConfidentialClientApplication(
        client_id,
        authority="https://login.microsoftonline.com/" + tenant_id,
        client_credential={"thumbprint": cert["thumbprint"], "private_key": cert["private_key"],})
    
    result = app.acquire_token_for_client(scopes=[scope])

    accessToken = result['access_token']
    return accessToken


if __name__ == "__main__":
    load_pem(client_cert_path)
    # print(get_token())

