import os
import hashlib
from tkinter import Tk, Label, Button, filedialog, messagebox, StringVar
from cryptography.fernet import Fernet


# =============================
#  Key Management
# =============================
def generate_key():
    """Generate and store a new encryption key."""
    key = Fernet.generate_key()
    with open("filekey.key", "wb") as key_file:
        key_file.write(key)
    return key


def load_key():
    """Load an existing key, or create one if not found."""
    if not os.path.exists("filekey.key"):
        return generate_key()
    with open("filekey.key", "rb") as key_file:
        return key_file.read()


# =============================
#  File Encryption / Decryption
# =============================
def encrypt_file(filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        original = file.read()

    encrypted = fernet.encrypt(original)
    enc_path = filepath + ".enc"

    with open(enc_path, "wb") as enc_file:
        enc_file.write(encrypted)

    return enc_path


def decrypt_file(filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as enc_file:
        encrypted = enc_file.read()

    try:
        decrypted = fernet.decrypt(encrypted)
    except Exception:
        return None  # wrong key or corrupted file

    if filepath.endswith(".enc"):
        output_file = filepath[:-4]
    else:
        output_file = filepath + "_decrypted"

    with open(output_file, "wb") as dec_file:
        dec_file.write(decrypted)

    return output_file


# =============================
#  Integrity Verification
# =============================
def generate_hash(filepath):
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)
    hash_value = sha.hexdigest()

    with open(filepath + ".hash", "w") as hash_file:
        hash_file.write(hash_value)
    return hash_value


def verify_hash(filepath):
    hash_path = filepath + ".hash"
    if not os.path.exists(hash_path):
        return None

    with open(hash_path, "r") as hash_file:
        stored_hash = hash_file.read()

    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)

    return stored_hash == sha.hexdigest()


# =============================
#  GUI Functions
# =============================
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        selected_file.set(file_path)


def do_encrypt():
    path = selected_file.get()
    if not path:
        messagebox.showwarning("Warning", "Please select a file first.")
        return

    key = load_key()
    enc_path = encrypt_file(path, key)
    generate_hash(path)
    messagebox.showinfo("Success", f"File encrypted successfully:\n{enc_path}")


def do_decrypt():
    path = selected_file.get()
    if not path:
        messagebox.showwarning("Warning", "Please select a file first.")
        return

    key = load_key()
    dec_path = decrypt_file(path, key)
    if dec_path:
        messagebox.showinfo("Success", f"File decrypted successfully:\n{dec_path}")
    else:
        messagebox.showerror("Error", "Decryption failed! Wrong key or corrupted file.")


def do_verify():
    path = selected_file.get()
    if not path:
        messagebox.showwarning("Warning", "Please select a file first.")
        return

    result = verify_hash(path)
    if result is None:
        messagebox.showwarning("Missing", "No hash file found for this file.")
    elif result:
        messagebox.showinfo("Integrity Check", "✅ File integrity verified successfully!")
    else:
        messagebox.showerror("Integrity Check", "⚠️ File integrity FAILED! File may be modified.")


# =============================
#  GUI Setup
# =============================
window = Tk()
window.title("File Encryption & Integrity Tool")
window.geometry("500x300")
window.resizable(False, False)

Label(window, text="🔐 File Encryption and Integrity Tool", font=("Arial", 14, "bold")).pack(pady=15)

selected_file = StringVar()
Label(window, textvariable=selected_file, wraplength=400, fg="blue").pack(pady=5)

Button(window, text="Select File", width=20, command=select_file).pack(pady=5)
Button(window, text="Encrypt File", width=20, command=do_encrypt).pack(pady=5)
Button(window, text="Decrypt File", width=20, command=do_decrypt).pack(pady=5)
Button(window, text="Verify Integrity", width=20, command=do_verify).pack(pady=5)
Button(window, text="Exit", width=20, command=window.destroy).pack(pady=10)

Label(window, text="© 2025 InfoSec Project", font=("Arial", 9)).pack(side="bottom", pady=5)

window.mainloop()
