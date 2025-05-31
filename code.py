import random
import string
import os
import json
import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip
import hashlib
from cryptography.fernet import Fernet
import base64

class PasswordGenerator:
    def __init__(self):
        self.passwords_file = "saved_passwords.json"
        self.key_file = "encryption.key"
        self._initialize_encryption()
        
    def _initialize_encryption(self):
        """Initializes or loads the encryption key."""
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
        else:
            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
        
        self.fernet = Fernet(key)
    
    def generate_password(self, length=12, use_uppercase=True, use_lowercase=True,
                          use_digits=True, use_special=True, avoid_similar=False):
        """Generates a random password based on specified criteria."""
        char_sets = []
        
        if use_lowercase:
            lowercase = string.ascii_lowercase
            char_sets.append(lowercase)
        
        if use_uppercase:
            uppercase = string.ascii_uppercase
            char_sets.append(uppercase)
        
        if use_digits:
            digits = string.digits
            char_sets.append(digits)
        
        if use_special:
            special = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
            char_sets.append(special)
        
        if not char_sets:
            raise ValueError("At least one character set must be selected.")
        
        # Combine all character sets
        all_chars = ''.join(char_sets)
        
        # Remove similar characters if needed
        if avoid_similar:
            similar_chars = "iIl1LoO0"
            all_chars = ''.join(c for c in all_chars if c not in similar_chars)
        
        # Select at least one character from each set
        password = []
        for char_set in char_sets:
            password.append(random.choice(char_set))
        
        # Fill the rest of the password
        while len(password) < length:
            password.append(random.choice(all_chars))
        
        # Shuffle the characters
        random.shuffle(password)
        
        return ''.join(password)
    
    def evaluate_password_strength(self, password):
        """Evaluates the password strength and returns a score and feedback."""
        score = 0
        feedback = []
        
        # Check length
        if len(password) < 8:
            feedback.append("Password is too short.")
        elif len(password) >= 12:
            score += 2
            feedback.append("Password length is good.")
        else:
            score += 1
            feedback.append("Password could be longer.")
        
        # Check character types
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Missing lowercase letters.")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Missing uppercase letters.")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Missing numbers.")
        
        if any(c in string.punctuation for c in password):
            score += 1
        else:
            feedback.append("Missing special characters.")
        
        # Evaluate password entropy
        entropy = len(password) * (
            sum([1 for _ in password if _.islower()]) > 0) * 1.5 +sum([1 for _ in password if _.isupper()]) * 1.5 +sum([1 for _ in password if _.isdigit()]) * 1.5 +sum([1 for _ in password if _ in string.punctuation]) * 2
        
        if entropy > 30:
            score += 2
            feedback.append("Password has high entropy.")
        
        # Final rating
        if score >= 7:
            strength = "Strong"
        elif score >= 5:
            strength = "Good"
        elif score >= 3:
            strength = "Medium"
        else:
            strength = "Weak"
        
        if not feedback:
            feedback.append("Password meets all security criteria.")
        
        return {
            "score": score,
            "strength": strength,
            "feedback": feedback
        }
    
    def save_password(self, service, username, password, master_password):
        """Saves the password to file with encryption."""
        hashed_master = self._hash_master_password(master_password)
        
        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        
        data = {}
        if os.path.exists(self.passwords_file):
            try:
                with open(self.passwords_file, "r") as file:
                    data = json.load(file)
            except (json.JSONDecodeError, FileNotFoundError):
                data = {}
        
        if 'passwords' not in data:
            data['passwords'] = []
            data['master_hash'] = hashed_master
        else:
            # Check if master password is correct
            if data.get('master_hash') != hashed_master:
                raise ValueError("Incorrect master password.")
        
        # Check if service already exists
        for entry in data['passwords']:
            if entry['service'] == service and entry['username'] == username:
                entry['password'] = encrypted_password
                break
        else:
            data['passwords'].append({
                'service': service,
                'username': username,
                'password': encrypted_password
            })
        
        with open(self.passwords_file, "w") as file:
            json.dump(data, file, indent=2)
    
    def get_saved_passwords(self, master_password):
        """Gets saved passwords from file and decrypts them."""
        if not os.path.exists(self.passwords_file):
            return []
        
        hashed_master = self._hash_master_password(master_password)
        
        with open(self.passwords_file, "r") as file:
            data = json.load(file)
        
        if data.get('master_hash') != hashed_master:
            raise ValueError("Incorrect master password.")
        
        result = []
        for entry in data['passwords']:
            decrypted_password = self.fernet.decrypt(entry['password'].encode()).decode()
            result.append({
                'service': entry['service'],
                'username': entry['username'],
                'password': decrypted_password
            })
        
        return result
    
    def _hash_master_password(self, password):
        """Creates a hash of the master password."""
        return hashlib.sha256(password.encode()).hexdigest()


class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("600x700")
        self.root.resizable(False, False)
        
        self.generator = PasswordGenerator()
        
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TCheckbutton", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10, "bold"))
        
        self.create_widgets()
    
    def create_widgets(self):
        """Creates the graphical interface."""
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Password generation tab
        generate_tab = ttk.Frame(notebook)
        notebook.add(generate_tab, text="Generate Passwords")
        
        # Saved passwords tab
        saved_tab = ttk.Frame(notebook)
        notebook.add(saved_tab, text="Saved Passwords")
        
        self.create_generate_tab(generate_tab)
        self.create_saved_tab(saved_tab)
    
    def create_generate_tab(self, parent):
        """Creates the tab for password generation."""
        # Options frame
        options_frame = ttk.LabelFrame(parent, text="Generation Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Password length
        ttk.Label(options_frame, text="Password length:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.length_var = tk.IntVar(value=12)
        length_scale = ttk.Scale(options_frame, from_=6, to=32, variable=self.length_var, orient=tk.HORIZONTAL)
        length_scale.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        
        length_label = ttk.Label(options_frame, textvariable=self.length_var, width=3)
        length_label.grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Character options
        self.uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Uppercase letters (A-Z)", variable=self.uppercase_var).grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=2)
        
        self.lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Lowercase letters (a-z)", variable=self.lowercase_var).grid(row=2, column=0, columnspan=3, sticky=tk.W, padx=5, pady=2)
        
        self.digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Digits (0-9)", variable=self.digits_var).grid(row=3, column=0, columnspan=3, sticky=tk.W, padx=5, pady=2)
        
        self.special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Special characters (!@#$...)", variable=self.special_var).grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=5, pady=2)
        
        self.avoid_similar_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Avoid similar characters (i, l, 1, I, o, 0, O)", variable=self.avoid_similar_var).grid(row=5, column=0, columnspan=3, sticky=tk.W, padx=5, pady=2)
        
        # Generate button
        generate_button = ttk.Button(parent, text="Generate Password", command=self.generate_password)
        generate_button.pack(pady=10)
        
        # Frame for displaying the password
        password_frame = ttk.LabelFrame(parent, text="Generated Password")
        password_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=self.password_var, font=("Courier", 12), width=40)
        password_entry.pack(fill=tk.X, padx=10, pady=10)
        
        button_frame = ttk.Frame(password_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        copy_button = ttk.Button(button_frame, text="Copy", command=self.copy_password)
        copy_button.pack(side=tk.LEFT, padx=5)
        
        save_button = ttk.Button(button_frame, text="Save", command=self.show_save_dialog)
        save_button.pack(side=tk.LEFT, padx=5)
        
        # Frame for password strength evaluation
        strength_frame = ttk.LabelFrame(parent, text="Password Strength Evaluation")
        strength_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.strength_var = tk.StringVar()
        strength_label = ttk.Label(strength_frame, textvariable=self.strength_var, font=("Arial", 10, "bold"))
        strength_label.pack(pady=5)
        
        self.progress_var = tk.DoubleVar()
        strength_progress = ttk.Progressbar(strength_frame, variable=self.progress_var, maximum=10)
        strength_progress.pack(fill=tk.X, padx=10, pady=5)
        
        self.feedback_text = tk.Text(strength_frame, height=4, width=40, wrap=tk.WORD, font=("Arial", 9))
        self.feedback_text.pack(fill=tk.X, padx=10, pady=5)
        self.feedback_text.config(state=tk.DISABLED)
    
    def create_saved_tab(self, parent):
        """Creates the tab for saved passwords."""
        # Authentication frame
        auth_frame = ttk.LabelFrame(parent, text="Authentication")
        auth_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(auth_frame, text="Master Password:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.master_password_var = tk.StringVar()
        master_entry = ttk.Entry(auth_frame, textvariable=self.master_password_var, show="*", width=30)
        master_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        load_button = ttk.Button(auth_frame, text="Load Passwords", command=self.load_saved_passwords)
        load_button.grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Frame for password list
        self.passwords_frame = ttk.LabelFrame(parent, text="Saved Passwords")
        self.passwords_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview for displaying passwords
        columns = ("service", "username", "password")
        self.password_tree = ttk.Treeview(self.passwords_frame, columns=columns, show="headings")
        
        self.password_tree.heading("service", text="Service")
        self.password_tree.heading("username", text="Username")
        self.password_tree.heading("password", text="Password")
        
        self.password_tree.column("service", width=150)
        self.password_tree.column("username", width=150)
        self.password_tree.column("password", width=200)
        
        scrollbar = ttk.Scrollbar(self.passwords_frame, orient=tk.VERTICAL, command=self.password_tree.yview)
        self.password_tree.configure(yscroll=scrollbar.set)
        
        self.password_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Contextual menu for copying
        self.context_menu = tk.Menu(self.password_tree, tearoff=0)
        self.context_menu.add_command(label="Copy password", command=self.copy_selected_password)
        
        self.password_tree.bind("<Button-3>", self.show_context_menu)
    
    def generate_password(self):
        """Generates a password based on selected options and updates the interface."""
        try:
            # Generate new password
            password = self.generator.generate_password(
                length=self.length_var.get(),
                use_uppercase=self.uppercase_var.get(),
                use_lowercase=self.lowercase_var.get(),
                use_digits=self.digits_var.get(),
                use_special=self.special_var.get(),
                avoid_similar=self.avoid_similar_var.get()
            )
            
            # Set password in interface
            self.password_var.set(password)
            
            # Evaluate password strength
            strength_data = self.generator.evaluate_password_strength(password)
            
            # Update strength indicator
            self.strength_var.set(f"Strength: {strength_data['strength']}")
            self.progress_var.set(strength_data['score'])
            
            # Update feedback
            self.feedback_text.config(state=tk.NORMAL)
            self.feedback_text.delete(1.0, tk.END)
            self.feedback_text.insert(tk.END, "\n".join(strength_data['feedback']))
            self.feedback_text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def copy_password(self):
        """Copies the password to clipboard."""
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copy", "Password has been copied to clipboard!")
    
    def show_save_dialog(self):
        """Displays the dialog for saving the password."""
        if not self.password_var.get():
            messagebox.showerror("Error", "There is no password to save.")
            return
        
        save_dialog = tk.Toplevel(self.root)
        save_dialog.title("Save Password")
        save_dialog.geometry("300x200")
        save_dialog.resizable(False, False)
        save_dialog.transient(self.root)
        save_dialog.grab_set()
        
        ttk.Label(save_dialog, text="Service:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        service_var = tk.StringVar()
        ttk.Entry(save_dialog, textvariable=service_var, width=25).grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(save_dialog, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        username_var = tk.StringVar()
        ttk.Entry(save_dialog, textvariable=username_var, width=25).grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(save_dialog, text="Master Password:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        master_var = tk.StringVar()
        ttk.Entry(save_dialog, textvariable=master_var, show="*", width=25).grid(row=2, column=1, padx=10, pady=5)
        
        def save():
            try:
                service = service_var.get()
                username = username_var.get()
                master_password = master_var.get()
                
                if not service or not username or not master_password:
                    messagebox.showerror("Error", "All fields are required.")
                    return
                
                self.generator.save_password(
                    service=service,
                    username=username,
                    password=self.password_var.get(),
                    master_password=master_password
                )
                
                messagebox.showinfo("Success", "Password has been saved successfully!")
                save_dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        ttk.Button(save_dialog, text="Save", command=save).grid(row=3, column=0, columnspan=2, pady=20)
    
    def load_saved_passwords(self):
        """Loads saved passwords using the master password."""
        try:
            master_password = self.master_password_var.get()
            if not master_password:
                messagebox.showerror("Error", "Enter the master password.")
                return
            
            passwords = self.generator.get_saved_passwords(master_password)
            
            # Clear the treeview
            for item in self.password_tree.get_children():
                self.password_tree.delete(item)
            
            # Add passwords to treeview
            for entry in passwords:
                masked_password = "•" * len(entry['password'])
                self.password_tree.insert("", tk.END, values=(
                    entry['service'],
                    entry['username'],
                    masked_password
                ), tags=(entry['password'],))
            
            if not passwords:
                messagebox.showinfo("Information", "No saved passwords exist.")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def show_context_menu(self, event):
        """Displays the context menu for treeview."""
        item = self.password_tree.identify_row(event.y)
        if item:
            self.password_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_selected_password(self):
        """Copies the selected password from treeview."""
        selected = self.password_tree.selection()
        if selected:
            item = selected[0]
            # Get the actual password from tags
            password = self.password_tree.item(item, "tags")[0]
            pyperclip.copy(password)
            messagebox.showinfo("Copy", "Password has been copied to clipboard!")


if __name__ == "__main__":
    # Check if all required packages are installed
    try:
        import pyperclip
        from cryptography.fernet import Fernet
    except ImportError:
        print("Installing required packages...")
        import sys
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyperclip", "cryptography"])
        print("Packages have been installed. The application will start now.")
    
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
