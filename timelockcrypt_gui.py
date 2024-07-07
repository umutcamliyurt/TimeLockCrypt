import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from timelockcrypt_common import encrypt_text, decrypt_text, encrypt_file, decrypt_file, convert_to_seconds

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TimeLockCrypt")
        self.root.configure(bg='#1e1e1e')  # Dark background
        self.root.geometry('750x375')  # Set window size
        self.root.resizable(False, False)  # Make window non-resizable

        # Define style parameters
        self.fg_color = 'white'  # Text color
        self.accent_color = '#4e4e4e'  # Accent color

        # Password label and entry
        self.password_label = tk.Label(self.root, text="Password:", fg=self.fg_color, bg='#1e1e1e')
        self.password_label.grid(row=0, column=1, padx=(10, 5), pady=20, sticky='e')

        self.password_entry = tk.Entry(self.root, show="*", bg='#333333', fg=self.fg_color, insertbackground=self.fg_color)
        self.password_entry.grid(row=0, column=2, padx=(5, 20), pady=20, sticky='ew')

        # Re-enter password label and entry
        self.password_reenter_label = tk.Label(self.root, text="Re-enter Password:", fg=self.fg_color, bg='#1e1e1e')
        self.password_reenter_label.grid(row=1, column=1, padx=(10, 5), pady=20, sticky='e')

        self.password_reenter_entry = tk.Entry(self.root, show="*", bg='#333333', fg=self.fg_color, insertbackground=self.fg_color)
        self.password_reenter_entry.grid(row=1, column=2, padx=(5, 20), pady=20, sticky='ew')

        # Output label above text display area
        self.output_label = tk.Label(self.root, text="Text Output:", fg=self.fg_color, bg='#1e1e1e')
        self.output_label.grid(row=2, column=1, columnspan=2, padx=10, pady=10, sticky='w')

        # Output text display area
        self.output_text = tk.Text(self.root, wrap=tk.NONE, bg='#333333', fg=self.fg_color, height=10)
        self.output_text.grid(row=3, column=1, columnspan=2, padx=10, pady=(0, 20), sticky='nsew')
        
        # Configure row 3 to resize vertically
        self.root.grid_rowconfigure(3, weight=1)

        # Buttons section
        buttons_frame = tk.Frame(self.root, bg='#1e1e1e')
        buttons_frame.grid(row=4, column=1, columnspan=2, pady=(10, 20), sticky='e')

        encrypt_buttons = [
            ("Encrypt Text", self.encrypt_text),
            ("Decrypt Text", self.decrypt_text),
            ("Encrypt File", self.encrypt_file),
            ("Decrypt File", self.decrypt_file),
            ("Copy Output", self.copy_output_text)
        ]

        for i, (text, command) in enumerate(encrypt_buttons):
            button = tk.Button(buttons_frame, text=text, command=command, bg=self.accent_color, fg=self.fg_color, activebackground=self.fg_color, activeforeground=self.accent_color)
            button.grid(row=0, column=i, padx=20, pady=5, sticky='ew')

        # Ensure widgets stretch horizontally with window resizing
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(2, weight=1)

    def get_passwords(self):
        password = self.password_entry.get()
        password_reenter = self.password_reenter_entry.get()
        if password != password_reenter:
            messagebox.showerror("Error", "Passwords do not match.")
            return None, None
        return password, password_reenter

    def encrypt_text(self):
        password, _ = self.get_passwords()
        if not password:
            return
        plaintext = simpledialog.askstring("Input", "Enter text to encrypt:")
        if plaintext:
            time_string = simpledialog.askstring("Input", "Enter time-lock duration (e.g., '30s', '5m', '2h', '1d', '1w'):")
            if time_string:
                try:
                    time_seconds = convert_to_seconds(time_string)
                    ciphertext, proof_iterations = encrypt_text(plaintext, password, time_seconds)
                    self.output_text.delete(1.0, tk.END)  # Clear previous content
                    self.output_text.insert(tk.END, ciphertext)
                    messagebox.showinfo("Encryption Completed", f"Text encrypted successfully.\nProof-of-work iterations (save this): {proof_iterations}")
                except ValueError as e:
                    messagebox.showerror("Error", str(e))


    def decrypt_text(self):
        password, _ = self.get_passwords()
        if not password:
            return
        ciphertext = simpledialog.askstring("Input", "Enter text to decrypt:")
        if ciphertext:
            pow_iterations = simpledialog.askinteger("Input", "Enter proof-of-work iterations:")
            if pow_iterations is not None:
                plaintext = decrypt_text(ciphertext, password, pow_iterations)
                if plaintext:
                    self.output_text.delete(1.0, tk.END)  # Clear previous content
                    self.output_text.insert(tk.END, plaintext)
                    messagebox.showinfo("Proof-of-Work Iterations", f"Proof-of-Work iterations used: {pow_iterations}")
                else:
                    messagebox.showerror("Error", "Decryption failed.")

    def encrypt_file(self):
        password, _ = self.get_passwords()
        if not password:
            return
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if file_path:
            time_string = simpledialog.askstring("Input", "Enter time-lock duration (e.g., '30s', '5m', '2h', '1d', '1w'):")
            if time_string:
                try:
                    time_seconds = convert_to_seconds(time_string)
                    encrypted_file_path, proof_iterations = encrypt_file(file_path, password, time_seconds)
                    self.output_text.delete(1.0, tk.END)  # Clear previous content
                    self.output_text.insert(tk.END, f"File encrypted successfully. Encrypted file saved at: {encrypted_file_path}\nProof-of-Work iterations (save this): {proof_iterations}")
                    messagebox.showinfo("Encryption Completed", f"File encrypted successfully.\nProof-of-work iterations (save this): {proof_iterations}")
                except ValueError as e:
                    messagebox.showerror("Error", str(e))


    def decrypt_file(self):
        password, _ = self.get_passwords()
        if not password:
            return
        file_path = filedialog.askopenfilename(title="Select file to decrypt")
        if file_path:
            pow_iterations = simpledialog.askinteger("Input", "Enter proof-of-work iterations:")
            if pow_iterations is not None:
                output_dir = filedialog.askdirectory(title="Select output directory")
                if not output_dir:
                    output_dir = None
                if decrypt_file(file_path, password, pow_iterations, output_dir):
                    self.output_text.delete(1.0, tk.END)  # Clear previous content
                    self.output_text.insert(tk.END, "File decrypted successfully.")
                    messagebox.showinfo("Proof-of-Work Iterations", f"Proof-of-Work iterations used: {pow_iterations}")
                else:
                    messagebox.showerror("Error", "Decryption failed.")

    def copy_output_text(self):
        # Function to copy the content of self.output_text to clipboard
        output_text_content = self.output_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(output_text_content)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
