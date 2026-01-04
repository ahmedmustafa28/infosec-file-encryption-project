# 🔐 File Encryption & Integrity Tool (GUI)

A Python-based desktop application that enables **secure file encryption, decryption, and integrity verification** using modern cryptographic techniques.  
This project was developed as a **semester project for Information Security**.

---

## 📌 Features

- 🔒 **File Encryption & Decryption**
  - Uses Fernet symmetric encryption (AES-based, authenticated encryption)
- 🗝️ **Automatic Key Management**
  - Securely generates and stores an encryption key
- 🧾 **Integrity Verification**
  - Implements SHA-256 hashing to detect file tampering
- 🖥️ **Graphical User Interface**
  - Simple and user-friendly interface built with Tkinter
- ⚠️ **Error Handling**
  - Detects corrupted files and incorrect keys during decryption

---

## 🛠️ Technologies Used

- **Python 3**
- **Tkinter** – GUI framework
- **cryptography (Fernet)** – Encryption & decryption
- **hashlib (SHA-256)** – File integrity verification
- **OS module** – File handling

---

## 🔐 Security Concepts Demonstrated

- Symmetric Key Cryptography
- Key Generation and Storage
- Cryptographic Hash Functions
- Data Integrity Verification
- Secure File Processing
