import hashlib
import os

CREDENTIALS_FILE = "credentials.txt"
MAX_ATTEMPTS = 3

def mitigated_hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    return hashlib.sha256((salt + password).encode()).hexdigest()

def register():
    """Registers a new user with a salted and hashed password."""
    username = input("Enter a username: ").strip()
    
    if user_exists(username):
        print("Username already taken. Try again.")
        return
    
    password = input("Enter a password: ").strip()
    salt = os.urandom(16).hex()  # Generates a random 16-byte salt
    hashed_password = mitigated_hash_password(password, salt)

    with open(CREDENTIALS_FILE, "a") as file:
        file.write(f"{username},{salt},{hashed_password}\n")
    
    print("Registration successful!")

def user_exists(username):
    """Checks if the username is already registered, skipping malformed lines."""
    if not os.path.exists(CREDENTIALS_FILE):
        return False
    
    with open(CREDENTIALS_FILE, "r") as file:
        for line in file:
            parts = line.strip().split(",")
            if len(parts) != 3:  # Ensure the line has exactly 3 parts
                continue  # Skip malformed lines
            
            stored_username, _, _ = parts
            if stored_username == username:
                return True
    return False

def verify_credentials(username, password):
    """Verifies the user's credentials using the stored hash and salt."""
    if not os.path.exists(CREDENTIALS_FILE):
        return False

    with open(CREDENTIALS_FILE, "r") as file:
        for line in file:
            parts = line.strip().split(",")
            if len(parts) != 3:  # Skip malformed lines
                continue  
            
            stored_username, salt, stored_hash = parts
            if stored_username == username:
                return mitigated_hash_password(password, salt) == stored_hash
    return False

def reset_password(username):
    """Allows the user to reset their password after three failed attempts."""
    new_password = input("Enter a new password: ").strip()
    salt = os.urandom(16).hex()  # Generate a new random salt
    new_hashed_password = mitigated_hash_password(new_password, salt)

    # Update the credentials file with the new password
    with open(CREDENTIALS_FILE, "r") as file:
        lines = file.readlines()
    
    with open(CREDENTIALS_FILE, "w") as file:
        for line in lines:
            stored_username, old_salt, old_hash = line.strip().split(",")
            if stored_username == username:
                file.write(f"{username},{salt},{new_hashed_password}\n")
            else:
                file.write(line)
    
    print("Password reset successful! Please log in with your new password.")

def login():
    """Handles user login with an attempt limit and forces a reset after 3 failures."""
    username = input("Enter your username: ").strip()
    
    if not user_exists(username):
        print("Username not found. Please register first.")
        return
    
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        password = input("Enter your password: ").strip()
        if verify_credentials(username, password):
            print("Login successful!")
            return
        else:
            attempts += 1
            print(f"Invalid password. Attempts remaining: {MAX_ATTEMPTS - attempts}")

    print("Too many failed attempts. You must reset your password.")
    reset_password(username)

def main():
    """Main menu for the authentication system."""
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
