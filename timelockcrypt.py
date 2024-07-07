import getpass
import timelockcrypt_common

if __name__ == "__main__":
    password = getpass.getpass("Enter password: ")
    password_reenter = getpass.getpass("Re-enter password: ")

    if password != password_reenter:
        print("Passwords do not match.")
        exit()

    action = input("Enter 'et' for encrypting text, 'ef' for encrypting a file, 'dt' for decrypting text, or 'df' for decrypting a file: ")

    if action == "et":
        plaintext = input("Enter text to encrypt: ")
        time_string = input("Enter time for timelockcrypt_common (e.g., '10m' for 10 minutes): ")
        try:
            time_seconds = timelockcrypt_common.convert_to_seconds(time_string)
            encrypted_data, proof_iterations = timelockcrypt_common.encrypt_text(plaintext, password, time_seconds)
            print(f"Encrypted text:\n{encrypted_data}")
            print(f"Proof-of-Work iterations performed: {proof_iterations}")
        except ValueError as e:
            print(f"Error: {str(e)}")

    elif action == "ef":
        file_path = input("Enter file path to encrypt: ")
        time_string = input("Enter time for timelockcrypt_common (e.g., '10m' for 10 minutes): ")
        try:
            time_seconds = timelockcrypt_common.convert_to_seconds(time_string)
            encrypted_file_path, proof_iterations = timelockcrypt_common.encrypt_file(file_path, password, time_seconds)
            print(f"File encrypted successfully. Encrypted file: {encrypted_file_path}")
            print(f"Proof-of-Work iterations performed: {proof_iterations}")
        except ValueError as e:
            print(f"Error: {str(e)}")

    elif action == "dt":
        encrypted_data = input("Enter encrypted text: ")
        pow_iterations = int(input("Enter number of iterations for proof of work: "))
        try:
            decrypted_text = timelockcrypt_common.decrypt_text(encrypted_data, password, pow_iterations)
            if decrypted_text:
                print(f"Decrypted text:\n{decrypted_text}")
        except ValueError as e:
            print(f"Error: {str(e)}")

    elif action == "df":
        file_path = input("Enter file path to decrypt: ")
        pow_iterations = int(input("Enter number of iterations for proof of work: "))
        output_dir = input("Enter directory to save decrypted file (press Enter for current directory): ").strip()
        try:
            decryption_success = timelockcrypt_common.decrypt_file(file_path, password, pow_iterations, output_dir)
            if decryption_success:
                pass
        except ValueError as e:
            print(f"Error: {str(e)}")

    else:
        print("Invalid action.")
