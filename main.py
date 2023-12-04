import hashlib
import json
import random

def generate_random_password():
    uppercase_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lowercase_letters = "abcdefghijklmnopqrstuvwxyz"
    digits = "123456789"
    special_chars = "!@#$%^&*"

    # Générer un mot de passe aléatoire
    password = (
        random.choice(uppercase_letters) +
        random.choice(lowercase_letters) +
        random.choice(digits) +
        random.choice(special_chars) +
        ''.join(random.choice(uppercase_letters + lowercase_letters + digits + special_chars) for _ in range(8))
    )

    # Mélanger les caractères du mot de passe pour plus d'aléatoire
    password_list = list(password)
    random.shuffle(password_list)
    shuffled_password = ''.join(password_list)
    return shuffled_password

def hash_password(password):
    # Utilisation de l'algorithme SHA-256 pour le hachage
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def load_passwords(filename="Passwords"):
    try:
        # Ouverture du fichier en mode lecture et vérifie s'il n'y a pas d'erreur
        with open(filename) as file:
            hashed_passwords = json.load(file)
    except FileNotFoundError:
        hashed_passwords = []
    return hashed_passwords

def duplicate_password(new_password, hashed_passwords):
    return any (hash_password(new_password) == hashed_pass for hashed_pass in hashed_passwords)

def save_passwords(hashed_passwords, filename="Passwords"):
    # Ouverture du fichier en mode écriture
    with open(filename, "w") as file:
        json.dump(hashed_passwords, file, indent=4)

def password_setting():
    hashed_passwords = load_passwords()

    while True:
        password_input = input("Veuillez entrer votre mot de passe (ou entrer 'g' pour générer un mot de passe aléatoire): ")

        if password_input.lower() == 'g':
            # Générer un mot de passe aléatoire
            password = generate_random_password()
            print("Votre mot de passe généré aléatoirement est :", password)
        else:
            password = password_input

            if len(password) < 8:
                print("Votre mot de passe doit contenir 8 caractères")
                continue

            if not any(c.isupper() for c in password):
                print("Votre mot de passe doit contenir au moins 1 majuscule")
                continue

            if not any(c.islower() for c in password):
                print("Votre mot de passe doit contenir au moins 1 minuscule")
                continue

            if not any(c.isdigit() for c in password):
                print("Votre mot de passe doit contenir au moins 1 chiffre")
                continue

            if not any(c in "!@#$%^&*" for c in password):
                print("Votre mot de passe doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *)")
                continue

            if duplicate_password(password, hashed_passwords):
                print("Ce mot de passe existe déjà. Veuillez en choisir un autre")
                continue


        # Hasher le mot de passe
        hashed_password = hash_password(password)
        print("Votre mot de passe est validé et hashé :\n", hashed_password)

        # Enregistrement du mot de passe dans le fichier "Passwords"
        save_option = input("Voulez-vous enregistrer ce mot de passe dans le fichier 'Passwords'? ('oui/non')").lower()
        if save_option == 'oui':
            hashed_passwords.append(hashed_password)
            save_passwords(hashed_passwords)
            print("Mot de passe est enregistré dans le fichier 'Passwords'", hashed_passwords)

        # Affichage de la liste des mots de passe
        show_option = input("Voulez-vous afficher la liste des mots de passe hashés ? ('oui/non')").lower()
        if show_option == 'oui':
            print("Liste des mots de passe hashés\n", hashed_passwords)

        # Ajout de nouveaux mots de passe
        continue_option = input("Voulez-vous entrer un autre mot de passe ? ('oui/non)").lower()
        if continue_option != 'oui':
            break

password_setting()