import tkinter as tk
from tkinter import ttk
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import base64
import time
import sys
from tkinter import messagebox, filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def encrypt_aes(key, plaintext):
    block_size = AES.block_size
    padded_plaintext = plaintext + (block_size - len(plaintext) % block_size) * chr(block_size - len(plaintext) % block_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(pad_key(key, block_size).encode('utf-8'), AES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(padded_plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def pad_key(key, block_size):
    if len(key) < block_size:
        key += ' ' * (block_size - len(key))  # Pad with spaces to reach the desired block size
    return key


def decrypt_aes(key, ciphertext):
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(pad_key(key, AES.block_size).encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext[AES.block_size:]).rstrip(b'\x00').decode('utf-8')
    return decrypted_text

def encrypt_des(key, plaintext):
    block_size = DES.block_size
    padded_plaintext = plaintext + (block_size - len(plaintext) % block_size) * chr(block_size - len(plaintext) % block_size)
    iv = get_random_bytes(DES.block_size)
    cipher = DES.new(pad_key(key, DES.block_size).encode('utf-8'), DES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(padded_plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_des(key, ciphertext):
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    iv = ciphertext[:DES.block_size]
    cipher = DES.new(pad_key(key, DES.block_size).encode('utf-8'), DES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext[DES.block_size:]).rstrip(b'\x00').decode('utf-8')
    return decrypted_text


def encrypt_rc4(key, plaintext):
    S = KSA(key)
    keystream = PRGA(S)
    ciphertext = []
    for byte in plaintext.encode('utf-8'):
        ciphertext_byte = byte ^ next(keystream)
        ciphertext.append(ciphertext_byte)
    return bytes(ciphertext).hex()

def KSA(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % key_length])) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) % 256]

def decrypt_rc4(key, ciphertext):
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext)
    except ValueError:
        return "Invalid hexadecimal ciphertext"

    S = KSA(key)
    keystream = PRGA(S)
    plaintext = []
    for byte in ciphertext_bytes:
        plaintext_byte = byte ^ next(keystream)
        plaintext.append(plaintext_byte)
    return bytes(plaintext).decode('utf-8')

def encrypt_text():
    selected_algorithm = algorithm_var.get()
    plaintext = plaintext_entry.get("1.0", "end-1c")
    key = key_entry.get()
    
    if selected_algorithm == "AES":
        ciphertext = encrypt_aes(key, plaintext)
    elif selected_algorithm == "DES":
        ciphertext = encrypt_des(key, plaintext)
    elif selected_algorithm == "RC4":
        ciphertext = encrypt_rc4(key, plaintext)
    else:
        ciphertext = "Invalid algorithm selection"
    
    ciphertext_output.config(state="normal")
    ciphertext_output.delete("1.0", "end")
    ciphertext_output.insert("1.0", ciphertext)
    ciphertext_output.config(state="disabled")

def decrypt_text():
    selected_algorithm = algorithm_var.get()
    ciphertext = ciphertext_entry.get("1.0", "end-1c")
    key = key_entry.get()
    decryption_key = decryption_key_entry.get()  # Get the decryption key from the entry field

    if selected_algorithm == "AES":
        decrypted_text = decrypt_aes(key, ciphertext)
    elif selected_algorithm == "DES":
        decrypted_text = decrypt_des(key, ciphertext)
    elif selected_algorithm == "RC4":
        decrypted_text = decrypt_rc4(key, ciphertext)
    else:
        decrypted_text = "Invalid algorithm selection"

    # Start measuring time complexity
    start_time = time.time()

    plaintext_output.config(state="normal")
    plaintext_output.delete("1.0", "end")

    # Check if the decryption key is correct
    if key == decryption_key:
        plaintext_output.insert("1.0", decrypted_text)
    else:
        plaintext_output.insert("1.0", "Incorrect decryption key")

    # End measuring time complexity
    end_time = time.time()

    # Calculate time complexity (elapsed time)
    time_complexity = end_time - start_time

    # Calculate space complexity (size of decrypted_text in bytes)
    space_complexity = sys.getsizeof(decrypted_text)

    # Display time and space complexity
    plaintext_output.insert("end", f"\nTime Complexity: {time_complexity:.6f} seconds\nSpace Complexity: {space_complexity} bytes")
    plaintext_output.config(state="disabled")


#asymmetric part

# Initialize global variables
private_key_rsa = None
public_key_rsa = None
private_key_dsa = None
public_key_dsa = None
original_message = ""
decryption_time = 0.0  # Initialize with default values
decryption_space = 0  # Initialize with default values

def generate_rsa_keys(folder_path):
    global private_key_rsa, public_key_rsa
    private_key_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key_rsa = private_key_rsa.public_key()
    
    private_key_path = f"{folder_path}/private_key_rsa.pem"
    public_key_path = f"{folder_path}/public_key_rsa.pem"
    
    private_pem = private_key_rsa.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(private_key_path, 'wb') as private_key_file:
        private_key_file.write(private_pem)
    
    public_pem = public_key_rsa.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(public_pem)
    
    messagebox.showinfo("RSA Keys Generated", f"RSA Keys generated and saved in {folder_path}")

def load_rsa_keys(folder_path):
    global private_key_rsa, public_key_rsa
    private_key_path = f"{folder_path}/private_key_rsa.pem"
    public_key_path = f"{folder_path}/public_key_rsa.pem"
    
    if private_key_path and public_key_path:
        with open(private_key_path, 'rb') as private_key_file:
            private_key_pem = private_key_file.read()
            private_key_rsa = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        
        with open(public_key_path, 'rb') as public_key_file:
            public_key_pem = public_key_file.read()
            public_key_rsa = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        
        messagebox.showinfo("RSA Keys Loaded", "RSA Keys loaded successfully.")
    else:
        messagebox.showerror("Error", "Please select both private and public RSA key files.")

def generate_dsa_keys(folder_path):
    global private_key_dsa, public_key_dsa
    private_key_dsa = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )
    
    public_key_dsa = private_key_dsa.public_key()
    
    private_key_path = f"{folder_path}/private_key_dsa.pem"
    public_key_path = f"{folder_path}/public_key_dsa.pem"
    
    private_pem = private_key_dsa.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(private_key_path, 'wb') as private_key_file:
        private_key_file.write(private_pem)
    
    public_pem = public_key_dsa.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(public_pem)
    
    messagebox.showinfo("DSA Keys Generated", f"DSA Keys generated and saved in {folder_path}")

def load_dsa_keys(folder_path):
    global private_key_dsa, public_key_dsa
    private_key_path = f"{folder_path}/private_key_dsa.pem"
    public_key_path = f"{folder_path}/public_key_dsa.pem"
    
    if private_key_path and public_key_path:
        with open(private_key_path, 'rb') as private_key_file:
            private_key_pem = private_key_file.read()
            private_key_dsa = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        
        with open(public_key_path, 'rb') as public_key_file:
            public_key_pem = public_key_file.read()
            public_key_dsa = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        
        messagebox.showinfo("DSA Keys Loaded", "DSA Keys loaded successfully.")
    else:
        messagebox.showerror("Error", "Please select both private and public DSA key files.")

def encrypt_rsa(plaintext, use_public_key):
    global private_key_rsa, public_key_rsa
    
    if use_public_key:
        key = public_key_rsa
    else:
        key = private_key_rsa
    
    ciphertext = key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(ciphertext, use_private_key):
    global private_key_rsa
    
    if use_private_key:
        key = private_key_rsa
    else:
        key = public_key_rsa
    
    try:
        start_time = time.time()
        plaintext = key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        ).decode('utf-8')
        end_time = time.time()
        
        # Calculate time complexity (in seconds)
        time_complexity = end_time - start_time
        
        # Calculate space complexity (in bytes)
        space_complexity = sys.getsizeof(plaintext)
        
        return plaintext, time_complexity, space_complexity
    except Exception as e:
        messagebox.showerror("Error", "RSA Decryption failed. Make sure the ciphertext is valid.")
        return "", 0, 0

def sign_dsa(message):
    global private_key_dsa
    
    if not private_key_dsa:
        messagebox.showerror("Error", "Please generate or load DSA keys before signing.")
        return
    
    signature = private_key_dsa.sign(
        message.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_dsa(signature, message):
    global public_key_dsa
    
    try:
        public_key_dsa.verify(
            signature,
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        return False

def measure_dsa_complexity():
    global start_time, end_time, space_complexity
    
    if start_time and end_time:
        time_elapsed = end_time - start_time
        space_complexity = sys.getsizeof(private_key_dsa) + sys.getsizeof(public_key_dsa)
        complexity_text.delete(1.0, tk.END)
        complexity_text.insert(tk.END, f"Time Complexity: {time_elapsed:.6f} seconds\nSpace Complexity: {space_complexity} bytes")
    else:
        messagebox.showerror("Error", "No DSA operation performed yet.")

def generate_rsa_keys_button_click():
    folder_path = filedialog.askdirectory(title="Select a folder to save RSA keys")
    if folder_path:
        generate_rsa_keys(folder_path)
    else:
        messagebox.showerror("Error", "Please select a folder to save RSA keys.")

def load_rsa_keys_button_click():
    folder_path = filedialog.askdirectory(title="Select a folder with RSA keys")
    if folder_path:
        load_rsa_keys(folder_path)
    else:
        messagebox.showerror("Error", "Please select a folder with RSA keys.")

def generate_dsa_keys_button_click():
    folder_path = filedialog.askdirectory(title="Select a folder to save DSA keys")
    if folder_path:
        generate_dsa_keys(folder_path)
    else:
        messagebox.showerror("Error", "Please select a folder to save DSA keys.")

def load_dsa_keys_button_click():
    folder_path = filedialog.askdirectory(title="Select a folder with DSA keys")
    if folder_path:
        load_dsa_keys(folder_path)
    else:
        messagebox.showerror("Error", "Please select a folder with DSA keys.")

# Button to encrypt RSA
def encrypt_rsa_button_click():
    if not (public_key_rsa and private_key_rsa):
        messagebox.showerror("Error", "Please generate or load RSA keys before encryption.")
        return
    
    plaintext = plaintext_entry_rsa.get()
    use_public_key = radio_var_encrypt_rsa.get() == 1
    
    start_time = time.time()  # Measure start time
    ciphertext = encrypt_rsa(plaintext, use_public_key)
    end_time = time.time()  # Measure end time
    
    # Calculate time complexity (in seconds)
    time_complexity = end_time - start_time
    
    # Calculate space complexity (in bytes)
    space_complexity = sys.getsizeof(ciphertext)
    
    # Display the ciphertext and complexity in the Text widget
    ciphertext_text_rsa.delete(1.0, tk.END)
    ciphertext_text_rsa.insert(tk.END, ciphertext.hex())
    
    # Display time and space complexity in the Text widget
    complexity_text_rsa.delete(1.0, tk.END)
    complexity_text_rsa.insert(tk.END, f"Time Complexity (Encryption): {time_complexity:.6f} seconds\nSpace Complexity (Encryption): {space_complexity} bytes")
# Button to decrypt RSA
def decrypt_rsa_button_click():
    global decryption_time, decryption_space  # Make sure to use the global variables
    
    ciphertext = ciphertext_input_rsa.get(1.0, tk.END).strip()  # Get ciphertext from the Text widget
    use_private_key = radio_var_decrypt_rsa.get() == 1
    
    start_time = time.time()  # Measure start time
    decrypted_text, decryption_time, decryption_space = decrypt_rsa(bytes.fromhex(ciphertext), use_private_key)
    end_time = time.time()  # Measure end time
    
    # Calculate time complexity (in seconds)
    decryption_time += end_time - start_time
    
    # Display the decrypted text
    decrypted_text_entry_rsa.delete(0, tk.END)
    decrypted_text_entry_rsa.insert(0, decrypted_text)
    
    # Measure and display the time and space complexity in the Text widget
    complexity_text_rsa.delete(1.0, tk.END)
    complexity_text_rsa.insert(tk.END, f"Decryption Time Complexity: {decryption_time:.6f} seconds\nDecryption Space Complexity: {decryption_space} bytes")


def measure_dsa_complexity_button_click():
    global start_time, end_time, space_complexity, complexity_text
    start_time = time.time()
    verify_dsa(signature_input.get(1.0, tk.END).strip(), message_entry.get())
    end_time = time.time()
    measure_dsa_complexity()

    # Update the complexity_text widget with time and space complexity
    complexity_text.delete(1.0, tk.END)
    complexity_text.insert(tk.END, f"Time Complexity (Verification): {end_time - start_time:.6f} seconds\nSpace Complexity (DSA): {space_complexity} bytes")



def measure_rsa_complexity():
    global decryption_time, decryption_space
    
    if decryption_time is not None and decryption_space is not None:
        complexity_text.delete(1.0, tk.END)
        complexity_text.insert(tk.END, f"Time Complexity (Decryption): {decryption_time:.6f} seconds\nSpace Complexity (Decryption): {decryption_space} bytes")
    else:
        messagebox.showerror("Error", "No RSA decryption operation performed yet.")


def sign_dsa_button_click():
    message = message_entry.get()
    signature = sign_dsa(message)
    signature_text.delete(1.0, tk.END)
    signature_text.insert(tk.END, signature.hex())

def verify_dsa_button_click():
    signature = signature_input.get(1.0, tk.END).strip()  # Get signature from the Text widget
    message = message_entry.get()
    valid = verify_dsa(bytes.fromhex(signature), message)
    if valid:
        messagebox.showinfo("DSA Verification", "Signature is valid.")
    else:
        messagebox.showerror("DSA Verification", "Signature is not valid.")

def measure_dsa_complexity_button_click():
    global start_time, end_time, space_complexity
    start_time = time.time()
    verify_dsa(signature_input.get(1.0, tk.END).strip(), message_entry.get())
    end_time = time.time()
    measure_dsa_complexity()

    
# Create a tkinter window
root = tk.Tk()
root.title("Symmetric and Asymmetric Encryption")

# Create two frames for symmetric and asymmetric encryption components
symmetric_frame = ttk.Frame(root)
symmetric_frame.pack(side="left", padx=10, pady=10)

rsa_frame = ttk.Frame(root)
rsa_frame.pack(side="right", padx=10, pady=10)
dsa_frame = ttk.Frame(root)
dsa_frame.pack(side="right", padx=10, pady=10)

# Symmetric Encryption Components (Left Frame)

symmetric_label = tk.Label( text="Symmetric Encryption", font=("Helvetica", 16))
symmetric_label.pack()


# Create input widgets
algorithm_label = tk.Label(text="Select Algorithm:")
algorithm_label.pack()
algorithm_var = tk.StringVar()
algorithm_var.set("AES")

# Use ttk.Combobox for the algorithm selection
algorithm_combobox = ttk.Combobox( textvariable=algorithm_var, values=["AES", "DES", "RC4"])
algorithm_combobox.pack()

plaintext_label = tk.Label(text="Enter plaintext:")
plaintext_label.pack()
plaintext_entry = tk.Text(height=5, width=40)
plaintext_entry.pack()

key_label = tk.Label(text="Enter encryption key:")
key_label.pack()
key_entry = tk.Entry(show="*")
key_entry.pack()

encrypt_button = tk.Button(text="Encrypt", command=encrypt_text)
encrypt_button.pack()

# Create output widget
ciphertext_label = tk.Label(text="Ciphertext:")
ciphertext_label.pack()
ciphertext_output = tk.Text( height=5, width=40, state="disabled")
ciphertext_output.pack()

# Create an entry widget for ciphertext
ciphertext_label = tk.Label(text="Enter ciphertext:")
ciphertext_label.pack()
ciphertext_entry = tk.Text( height=5, width=40)
ciphertext_entry.pack()

# Add a decryption key entry field
decryption_key_label = tk.Label(text="Enter decryption key:")
decryption_key_label.pack()
decryption_key_entry = tk.Entry( show="*")
decryption_key_entry.pack()

# Create the Decrypt button
decrypt_button = tk.Button(text="Decrypt", command=decrypt_text)
decrypt_button.pack()

# Add an output text widget
plaintext_output_label = tk.Label( text="Decrypted Text:")
plaintext_output_label.pack()
plaintext_output = tk.Text( height=5, width=40, state="disabled")
plaintext_output.pack()


# RSA Encryption Components (Right Frame)

rsa_label = tk.Label(rsa_frame, text="Asymmetric Encryption", font=("Helvetica", 16))
rsa_label.pack()

# Create a notebook widget to contain tabs
notebook = ttk.Notebook(rsa_frame)
notebook.pack(fill='both', expand='yes')

# Create tabs for RSA and DSA operations
rsa_frame = ttk.Frame(notebook)
dsa_frame = ttk.Frame(notebook)

notebook.add(rsa_frame, text="RSA")
notebook.add(dsa_frame, text="DSA")

# RSA Tab
# Button to generate RSA keys
generate_rsa_keys_button = tk.Button(rsa_frame, text="Generate RSA Keys", command=generate_rsa_keys_button_click)
generate_rsa_keys_button.pack()

# Button to load RSA keys
load_rsa_keys_button = tk.Button(rsa_frame, text="Load RSA Keys", command=load_rsa_keys_button_click)
load_rsa_keys_button.pack()

# Label and entry for RSA plaintext
plaintext_label_rsa = tk.Label(rsa_frame, text="Enter RSA plaintext:")
plaintext_label_rsa.pack()
plaintext_entry_rsa = tk.Entry(rsa_frame)
plaintext_entry_rsa.pack()

# Radio buttons for RSA encryption choice
radio_var_encrypt_rsa = tk.IntVar()
public_key_encrypt_radio_rsa = tk.Radiobutton(rsa_frame, text="Encrypt with Public Key", variable=radio_var_encrypt_rsa, value=1)
private_key_encrypt_radio_rsa = tk.Radiobutton(rsa_frame, text="Encrypt with Private Key", variable=radio_var_encrypt_rsa, value=2)
public_key_encrypt_radio_rsa.pack()
private_key_encrypt_radio_rsa.pack()

# Button to encrypt RSA
encrypt_button_rsa = tk.Button(rsa_frame, text="Encrypt RSA", command=encrypt_rsa_button_click)
encrypt_button_rsa.pack()

# Label and text widget for RSA ciphertext
ciphertext_label_rsa = tk.Label(rsa_frame, text="RSA Ciphertext:")
ciphertext_label_rsa.pack()
ciphertext_text_rsa = tk.Text(rsa_frame, height=5, width=40)
ciphertext_text_rsa.pack()

# Text widget for RSA ciphertext input
ciphertext_input_label_rsa = tk.Label(rsa_frame, text="Enter RSA ciphertext:")
ciphertext_input_label_rsa.pack()
ciphertext_input_rsa = tk.Text(rsa_frame, height=3, width=40)
ciphertext_input_rsa.pack()

# Radio buttons for RSA decryption choice
radio_var_decrypt_rsa = tk.IntVar()
private_key_decrypt_radio_rsa = tk.Radiobutton(rsa_frame, text="Decrypt with Private Key", variable=radio_var_decrypt_rsa, value=1)
public_key_decrypt_radio_rsa = tk.Radiobutton(rsa_frame, text="Decrypt with Public Key", variable=radio_var_decrypt_rsa, value=2)
private_key_decrypt_radio_rsa.pack()
public_key_decrypt_radio_rsa.pack()

# Button to decrypt RSA
decrypt_button_rsa = tk.Button(rsa_frame, text="Decrypt RSA", command=decrypt_rsa_button_click)
decrypt_button_rsa.pack()

# Label and entry for decrypted RSA text
decrypted_text_label_rsa = tk.Label(rsa_frame, text="Decrypted RSA Text:")
decrypted_text_label_rsa.pack()
decrypted_text_entry_rsa = tk.Entry(rsa_frame)
decrypted_text_entry_rsa.pack()
# Text widget for displaying RSA complexity
complexity_text_rsa_label = tk.Label(rsa_frame, text="Time and Space Complexity (RSA):")
complexity_text_rsa_label.pack()
complexity_text_rsa = tk.Text(rsa_frame, height=4, width=40)
complexity_text_rsa.pack()
# DSA Tab
# Button to generate DSA keys
generate_dsa_keys_button = tk.Button(dsa_frame, text="Generate DSA Keys", command=generate_dsa_keys_button_click)
generate_dsa_keys_button.pack()

# Button to load DSA keys
load_dsa_keys_button = tk.Button(dsa_frame, text="Load DSA Keys", command=load_dsa_keys_button_click)
load_dsa_keys_button.pack()

# Label and entry for DSA message
message_label = tk.Label(dsa_frame, text="Enter DSA Message:")
message_label.pack()
message_entry = tk.Entry(dsa_frame)
message_entry.pack()

# Button to sign DSA
sign_button = tk.Button(dsa_frame, text="Sign DSA", command=sign_dsa_button_click)
sign_button.pack()

# Label and text widget for DSA signature
signature_label = tk.Label(dsa_frame, text="DSA Signature:")
signature_label.pack()
signature_text = tk.Text(dsa_frame, height=5, width=40)
signature_text.pack()

# Text widget for DSA signature input
signature_input_label = tk.Label(dsa_frame, text="Enter DSA signature:")
signature_input_label.pack()
signature_input = tk.Text(dsa_frame, height=3, width=40)
signature_input.pack()

# Button to verify DSA
verify_button = tk.Button(dsa_frame, text="Verify DSA", command=verify_dsa_button_click)
verify_button.pack()

# Button to measure DSA complexity
measure_complexity_button = tk.Button(dsa_frame, text="Measure DSA Complexity", command=measure_dsa_complexity_button_click)
measure_complexity_button.pack()

# Text widget for displaying DSA time and space complexity
complexity_text = tk.Text(dsa_frame, height=2, width=40)
complexity_text.pack()
root.mainloop()