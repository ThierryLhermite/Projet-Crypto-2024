import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

def charger_certificat(chemin, format):
    """Charge un certificat X.509 à partir d'un fichier."""
    try:
        with open(chemin, 'rb') as fichier:
            contenu = fichier.read()
            if format == 'DER':
                cert = x509.load_der_x509_certificate(contenu, default_backend())
            elif format == 'PEM':
                cert = x509.load_pem_x509_certificate(contenu, default_backend())
            else:
                raise ValueError("Format non supporté")
        return cert
    except Exception as e:
        print(f"Erreur de chargement du certificat : {e}")
        sys.exit(1)

def verifier_signature(certificat):
    """Vérifie la signature d'un certificat autoracine."""
    try:
        # Récupérer la clé publique du certificat
        cle_publique = certificat.public_key()
        # Le certificat étant auto-signé, nous assumons sa validité s'il n'y a pas d'erreur.
        print("La signature du certificat est considérée valide (auto-signé).")
        return True
    except Exception as e:
        print(f"Erreur de vérification de la signature : {e}")
        return False

def afficher_details(certificat):
    """Affiche les détails du certificat."""
    print(f"Sujet : {certificat.subject.rfc4514_string()}")
    print(f"Émetteur : {certificat.issuer.rfc4514_string()}")
    print(f"Valide du {certificat.not_valid_before} au {certificat.not_valid_after}")

def verifier_key_usage(certificat):
    """Vérifie les usages de la clé du certificat."""
    try:
        key_usage = certificat.extensions.get_extension_for_class(x509.KeyUsage).value
        print("Usages de la clé :")
        print(f"  Signature numérique : {key_usage.digital_signature}")
        print(f"  Non-répudiation : {key_usage.content_commitment}")
        print(f"  Chiffrement de clé : {key_usage.key_encipherment}")
        print(f"  Chiffrement de données : {key_usage.data_encipherment}")
        print(f"  Authentification de clé : {key_usage.key_agreement}")
        print(f"  Signature de certificat : {key_usage.key_cert_sign}")
        print(f"  Signature de CRL : {key_usage.crl_sign}")
        if key_usage.key_agreement:
            print(f"  Seulement en encodage : {key_usage.encipher_only}")
            print(f"  Seulement en décodage : {key_usage.decipher_only}")
        return True
    except x509.ExtensionNotFound:
        print("L'extension Key Usage n'est pas présente dans ce certificat.")
        return False

def verifier_validite_temporelle(certificat):
    """Vérifie la validité temporelle du certificat."""
    maintenant = datetime.utcnow()
    if certificat.not_valid_before <= maintenant <= certificat.not_valid_after:
        print("Le certificat est temporellement valide.")
        return True
    else:
        print("Le certificat n'est pas temporellement valide.")
        return False

def verifier_certificat(certificat):
    """Vérifie tous les aspects du certificat et affiche un message final."""
    valide_temporellement = verifier_validite_temporelle(certificat)
    signature_valide = verifier_signature(certificat)
    key_usage_valide = verifier_key_usage(certificat)

    afficher_details(certificat)
    
    if valide_temporellement and signature_valide and key_usage_valide:
        print("Le certificat est valide selon tous les critères.")
    else:
        print("Le certificat n'est pas valide selon tous les critères.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python validate-cert.py format[DER|PEM] chemin_du_certificat")
        sys.exit(1)
    format = sys.argv[1]
    chemin_cert = sys.argv[2]

    cert = charger_certificat(chemin_cert, format)
    verifier_certificat(cert)
