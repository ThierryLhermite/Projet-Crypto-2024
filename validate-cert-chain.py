# Script to validate a certificate chain
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def verifier_chaine(certificats):
    resultat_verification = []
    chaine_valide = True
    
    for i in range(len(certificats) - 1):
        certificat_emetteur = certificats[i + 1]
        certificat = certificats[i]

        # Vérifiez que le certificat émetteur a la capacité de signer d'autres certificats
        try:
            basic_constraints = certificat_emetteur.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not basic_constraints.ca:
                resultat_verification.append(f"Certificat émetteur {i+1} a l'extension BasicConstraints mais n'est pas autorisé à signer d'autres certificats.")
                chaine_valide = False
            else:
                resultat_verification.append(f"Certificat émetteur {i+1} a l'extension BasicConstraints et est autorisé à signer d'autres certificats.")
        except x509.ExtensionNotFound:
            resultat_verification.append(f"Certificat émetteur {i+1} n'a pas l'extension BasicConstraints.")
            chaine_valide = False

        # Vérifiez la signature du certificat avec la clé publique de l'émetteur
        try:
            certificat_emetteur.public_key().verify(
                certificat.signature,
                certificat.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificat.signature_hash_algorithm,
            )
            resultat_verification.append(f"Signature du certificat {i} vérifiée avec succès.")
        except Exception as e:
            resultat_verification.append(f"Erreur de validation de la signature pour le certificat {i}: {str(e)}")
            chaine_valide = False

    return resultat_verification, chaine_valide

def charger_certificat(chemin):
    with open(chemin, 'rb') as fichier:
        contenu = fichier.read()
        return x509.load_pem_x509_certificate(contenu)

def afficher_usage():
    print("Usage: python validate-cert-chain.py certificat_final certificat_intermediaire certificat_racine")
    print("Exemple: python validate-cert-chain.py blizzard.pem AmazonRSA.crt AmazonRootCA.crt")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        afficher_usage()
        sys.exit(1)

    # Chemins des certificats
    chemins_certificats = sys.argv[1:]

    # Charger les certificats
    try:
        certificats = [charger_certificat(chemin) for chemin in chemins_certificats]
    except Exception as e:
        print(f"Erreur lors du chargement des certificats: {e}")
        sys.exit(1)

    # Vérifier la chaîne de certificats
    try:
        resultats, chaine_valide = verifier_chaine(certificats)
        for resultat in resultats:
            print(resultat)
        if chaine_valide:
            print("Chaîne de certificats valide.")
        else:
            print("Chaîne de certificats invalide.")
    except ValueError as e:
        print(f"Erreur de validation de la chaîne de certificats: {e}")
        sys.exit(1)
