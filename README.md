# 🔐 Password Generator & Manager

A secure and user-friendly Python application that helps you generate strong passwords, evaluate their strength, and securely store them for future use.

## ✨ Features

### 🎲 Random Password Generation
Create strong passwords with customizable options:
- Adjustable password length (6-32 characters)
- Include/exclude uppercase letters, lowercase letters, digits, and special characters
- Option to avoid similar-looking characters (i, l, 1, I, o, 0, O)

### 📊 Password Strength Evaluation
Instantly analyze your passwords with:
- Strength score and rating (Weak, Medium, Good, Strong)
- Detailed feedback on how to improve security
- Visual strength indicator

### 🔒 Secure Password Storage
Store your passwords safely:
- AES-256 encryption using Fernet
- Master password protection
- Encrypted local storage

### 👁️ User-Friendly Interface
- Clean, tabbed interface
- Easy-to-use controls
- Password masking for security
- Right-click options for quick actions

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- Required Python packages: `tkinter`, `pyperclip`, `cryptography`

### Quick Start

Clone this repository:

```bash
git clone https://github.com/yourusername/password-generator.git
cd password-generator
```
Install required dependencies:
```bash
pip install pyperclip cryptography

```

Run the application:
``` bash 
python password_generator.py
```
## 🛠️ Usage
Generating Passwords
Navigate to the "Generate Passwords" tab.

Adjust the password length using the slider.

Select character types to include (uppercase, lowercase, digits, special characters).

Click "Generate Password" to create a new password.

Use the "Copy" button to copy the password to your clipboard.

Analyze the strength feedback to ensure the generated password meets security standards.

Saving Passwords
After generating a password, click "Save".

Enter the service name and username.

Create a master password (for first-time use) or enter your existing one.

Click "Save" to securely store your password.

Retrieving Passwords
Navigate to the "Saved Passwords" tab.

Enter your master password.

Click "Load Passwords" to load saved entries.

Right-click on any entry to copy the password to your clipboard.

## 🔐 Security Information
All passwords are encrypted using Fernet symmetric encryption (AES-256).

The master password is never stored directly, only a secure hash is kept.

Passwords are masked in the interface for privacy.

The application stores data locally, not on any remote servers.

## 🧩 How It Works
The application uses a combination of technologies to ensure security and functionality:

Random module: For secure password generation.

Cryptography.fernet: For AES-256 encryption of stored passwords.

Hashlib: For securely hashing the master password.

Tkinter: For the graphical user interface (GUI).

JSON: For structured data storage.

## 📝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository.

Create your feature branch (git checkout -b feature/amazing-feature).

Commit your changes (git commit -m 'Add some amazing feature').

Push to the branch (git push origin feature/amazing-feature).

Open a Pull Request.

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements
Icons by FontAwesome.

Inspired by modern password management tools.

Built with Python and ❤️.


