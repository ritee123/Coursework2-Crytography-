import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from AES_CBC import aes_cbc_encrypt, aes_cbc_decrypt
from chacha20 import generate_combined_key
import os
import datetime
from PIL import Image, ImageTk

def open_file(file_path):
    """Open file with default system application"""
    try:
        if os.name == 'nt':  # For Windows
            os.startfile(file_path)
        else:  # For Linux/Mac
            import subprocess
            subprocess.call(('xdg-open', file_path))
    except Exception as e:
        messagebox.showerror("Error", f"Could not open file: {str(e)}")

def decrypt_file(encrypted_data, file_label, button):
    def on_decrypt():
        entered_key = key_entry.get()
        if not entered_key:
            messagebox.showerror("Error", "Please enter the key")
            return
            
        try:
            # Convert hex string back to bytes
            key_bytes = bytes.fromhex(entered_key)
            
            # Decrypt the data
            decrypted_data = aes_cbc_decrypt(encrypted_data, key_bytes)
            
            # Get original filename
            label_text = file_label.cget("text")
            original_filename = label_text.split("Original File:")[-1].strip()
            
            # Create decryption folder
            decrypted_folder = "decrypted_files"
            if not os.path.exists(decrypted_folder):
                os.makedirs(decrypted_folder)

            # Save decrypted file
            decrypted_path = os.path.join(decrypted_folder, original_filename)
            
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)
                f.flush()
                os.fsync(f.fileno())
            
            # Get the receiver's frame (where the decrypt button is)
            receiver_frame = button.master
            
            # Create decrypted file frame
            decrypted_frame = tk.Frame(receiver_frame, bg='blue', padx=10, pady=5, relief="solid", bd=2)
            
            # Show decrypted file info
            decrypted_label = tk.Label(decrypted_frame,
                                     text=f"Decrypted File: {original_filename}",
                                     bg='blue', fg='white', wraplength=250)
            decrypted_label.pack(padx=5, pady=5)
            
            # Add button to view decrypted file
            open_dec_button = tk.Button(decrypted_frame, text="View Decrypted File",
                                      command=lambda: open_file(decrypted_path))
            open_dec_button.pack(pady=5)
            
            # Pack the decrypted frame in the receiver's frame
            decrypted_frame.pack(pady=5)
            
            # Show success message
            messagebox.showinfo("Success", f"File decrypted successfully!")
            decrypt_popup.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    # Create decrypt popup
    decrypt_popup = tk.Toplevel()
    decrypt_popup.title("Decrypt File")
    decrypt_popup.geometry("300x150")

    key_label = tk.Label(decrypt_popup, text="Enter the key:")
    key_label.pack(pady=5)

    key_entry = tk.Entry(decrypt_popup, width=40)
    key_entry.pack(pady=5)

    decrypt_button = tk.Button(decrypt_popup, text="Decrypt", command=on_decrypt)
    decrypt_button.pack(pady=5)

def view_encrypted_file(encrypted_data, file_label):
    """Show popup for key entry and view decrypted file"""
    # Create decrypt popup
    decrypt_popup = tk.Toplevel()
    decrypt_popup.title("Enter Key")
    decrypt_popup.geometry("300x150")

    key_label = tk.Label(decrypt_popup, text="Enter the key to view file:")
    key_label.pack(pady=5)

    key_entry = tk.Entry(decrypt_popup, width=40)
    key_entry.pack(pady=5)

    def decrypt_and_view():
        entered_key = key_entry.get()
        if not entered_key:
            messagebox.showerror("Error", "Please enter the key")
            return
            
        try:
            # Convert hex string back to bytes
            key_bytes = bytes.fromhex(entered_key)
            
            # Decrypt the data
            decrypted_data = aes_cbc_decrypt(encrypted_data, key_bytes)
            
            # Get original filename
            label_text = file_label.cget("text")
            lines = label_text.split('\n')
            original_filename = lines[0].replace(".enc", "")
            
            # Create temporary file for viewing
            temp_folder = "temp_files"
            if not os.path.exists(temp_folder):
                os.makedirs(temp_folder)

            temp_path = os.path.join(temp_folder, original_filename)
            
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)
                f.flush()
                os.fsync(f.fileno())
            
            # Get the main encrypted file frame (red frame)
            main_frame = file_label.master.master
            
            # Remove any existing decrypted file frame
            for widget in main_frame.winfo_children():
                if isinstance(widget, tk.Frame) and widget.cget('bg') == 'blue':
                    widget.destroy()
            
            # Create a frame for the decrypted file with blue background
            decrypted_file_frame = tk.Frame(main_frame, bg='blue', padx=10, pady=5, relief="solid", bd=2)
            
            # Create a frame for the file info to allow for bullet point
            file_info_frame = tk.Frame(decrypted_file_frame, bg='blue')
            file_info_frame.pack(fill="x", padx=5, pady=5)
            
            # Add bullet point
            bullet = tk.Label(file_info_frame, text="•", bg='blue', fg='white')
            bullet.pack(side="left", padx=(0,5))
            
            # Show file info with size
            file_size = os.path.getsize(temp_path)
            file_size_kb = file_size / 1024  # Convert to KB
            file_ext = os.path.splitext(original_filename)[1][1:].upper()
            
            file_info = f"{original_filename}\n{file_size_kb:.1f} KB, {file_ext} File"
            
            decrypted_label = tk.Label(file_info_frame, 
                                     text=file_info,
                                     bg='blue', 
                                     fg='white',
                                     justify="left",
                                     wraplength=250)
            decrypted_label.pack(side="left", fill="x")
            
            # Add Open and Save as... buttons frame
            button_frame = tk.Frame(decrypted_file_frame, bg='blue')
            button_frame.pack(fill="x", padx=5, pady=5)
            
            open_button = tk.Button(button_frame, text="Open",
                                  command=lambda: open_file(temp_path),
                                  width=15)
            open_button.pack(side="left", padx=5)
            
            save_button = tk.Button(button_frame, text="Save as...",
                                  command=lambda: save_file_as(temp_path),
                                  width=15)
            save_button.pack(side="left", padx=5)
            
            # Simply pack at the end of the main frame
            decrypted_file_frame.pack(pady=5)
            
            decrypt_popup.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            print(f"Debug - Error details: {e}")  # Add debug print

    view_button = tk.Button(decrypt_popup, text="View File", command=decrypt_and_view)
    view_button.pack(pady=5)

def display_file_info_user1(filename, file_size_kb, file_type):
    # Create a container frame for left-side chat bubble
    container_frame = tk.Frame(user1_frame, bg='')
    container_frame.pack(fill="x", padx=(20, 100), pady=5)  # More padding on right
    
    # Create chat bubble frame with blue background
    file_frame = tk.Frame(container_frame, bg='blue', padx=10, pady=5)
    file_frame.pack(anchor="w", fill="x")  # Align to left
    
    # Add rounded corners effect
    canvas = tk.Canvas(file_frame, bg='blue', bd=0, highlightthickness=0, height=100)
    canvas.pack(fill="both", expand=True)
    
    # File info with bullet point
    file_info = f"• {filename}\n   {file_size_kb:.1f} KB, {file_type} File"
    file_label = tk.Label(canvas, 
                         text=file_info,
                         bg='blue', 
                         fg='white',
                         justify="left",
                         wraplength=250)
    file_label.pack(padx=5, pady=5, anchor="w")
    
    # Buttons frame
    button_frame = tk.Frame(canvas, bg='blue')
    button_frame.pack(fill="x", padx=5, pady=5)
    
    open_button = tk.Button(button_frame, text="Open",
                           command=lambda: open_file(filename),
                           width=15)
    open_button.pack(side="left", padx=5)
    
    save_button = tk.Button(button_frame, text="Save as...",
                           command=lambda: save_file_as(filename),
                           width=15)
    save_button.pack(side="left", padx=5)
    
    return file_frame

def display_file_info_user2(filename, file_size_kb, file_type, encrypted_data=None):
    # Create container frame
    container_frame = tk.Frame(user2_frame, bg='')
    container_frame.pack(fill="x", padx=(100, 20), pady=5)
    
    # Create main frame with slight transparency
    file_frame = tk.Frame(container_frame, bg='blue', padx=15, pady=10)
    file_frame.pack(anchor="e", fill="x")
    
    # File info with bullet point
    info_frame = tk.Frame(file_frame, bg='blue')
    info_frame.pack(fill="x", pady=(0,5))
    
    bullet = tk.Label(info_frame, text="•", fg='white', bg='blue')
    bullet.pack(side="left", padx=(0,5))
    
    file_info = f"{filename}\n{file_size_kb:.1f} KB, {'ENC' if filename.endswith('.enc') else file_type} File"
    file_label = tk.Label(info_frame, 
                         text=file_info,
                         fg='white',
                         bg='blue',
                         justify="left",
                         font=('Arial', 10))
    file_label.pack(side="left")
    
    if filename.endswith('.enc'):
        decrypt_button = tk.Button(file_frame, text="Decrypt File",  # Changed button text
                               command=lambda: decrypt_file(encrypted_data, file_label),  # Changed function name
                               bg='white',
                               fg='black',
                               relief="flat")
        decrypt_button.pack(pady=(5,0))
    else:
        # Button frame
        button_frame = tk.Frame(file_frame, bg='#1a1a1aE6')
        button_frame.pack(fill="x", pady=(5,0))
        
        open_button = tk.Button(button_frame, text="Open",
                               command=lambda: open_file(filename),
                               width=15,
                               bg='white',
                               fg='black',
                               relief="flat")
        open_button.pack(side="left", padx=5)
        
        save_button = tk.Button(button_frame, text="Save as...",
                               command=lambda: save_file_as(filename),
                               width=15,
                               bg='white',
                               fg='black',
                               relief="flat")
        save_button.pack(side="left", padx=5)
    
    return file_frame

def upload_and_encrypt_user1():
    file_path = file_path_var.get()  # Use the path from the entry
    if not file_path:
        return
        
    # Create key popup
    key_popup = tk.Toplevel()
    key_popup.title("Key Generation")
    key_popup.geometry("400x100")
    
    key_var = tk.StringVar()
    
    # Create frame for key generation
    key_frame = tk.Frame(key_popup)
    key_frame.pack(fill="x", padx=10, pady=10)
    
    key_label = tk.Label(key_frame, text="Generated Key:")
    key_label.pack(side="left", padx=(0,10))
    
    key_entry = tk.Entry(key_frame, textvariable=key_var, width=30)
    key_entry.pack(side="left", padx=(0,10))
    
    def generate_key():
        key = generate_combined_key()
        key_var.set(key.hex())  # Store key as hex string
    
    generate_button = tk.Button(key_frame, text="Generate Key", command=generate_key)
    generate_button.pack(side="left")
    
    def send_file():
        key = key_var.get()
        if not key:
            messagebox.showerror("Error", "Please generate a key first")
            return

        try:
            # Convert hex string back to bytes
            key_bytes = bytes.fromhex(key)
            
            # Read and encrypt file
            with open(file_path, 'rb') as f:
                file_data = f.read()

            encrypted_data = aes_cbc_encrypt(file_data, key_bytes)
            
            # Save encrypted file
            encrypted_folder = "encrypted_files"
            if not os.path.exists(encrypted_folder):
                os.makedirs(encrypted_folder)
            
            original_filename = os.path.basename(file_path)
            encrypted_path = os.path.join(encrypted_folder, original_filename + ".enc")
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
                f.flush()
                os.fsync(f.fileno())
            
            # Display original file on User 1's side (sender)
            user1_file_frame = tk.Frame(user1_frame, bg='blue', padx=10, pady=5, relief="solid", bd=2)
            
            # Create a frame for the file info to allow for bullet point
            file_info_frame = tk.Frame(user1_file_frame, bg='blue')
            file_info_frame.pack(fill="x", padx=5, pady=5)
            
            # Add bullet point
            bullet = tk.Label(file_info_frame, text="•", bg='blue', fg='white')
            bullet.pack(side="left", padx=(0,5))
            
            # Show file info with size in a more compact format
            file_size = os.path.getsize(file_path)
            file_size_kb = file_size / 1024  # Convert to KB
            
            file_info = f"{original_filename}\n{file_size_kb:.1f} KB, {os.path.splitext(original_filename)[1][1:].upper()} File"
            
            file_label = tk.Label(file_info_frame, 
                                text=file_info,
                                bg='blue', 
                                fg='white',
                                justify="left",
                                wraplength=250)
            file_label.pack(side="left", fill="x")
            
            # Add Open and Save as... buttons frame
            button_frame = tk.Frame(user1_file_frame, bg='blue')
            button_frame.pack(fill="x", padx=5, pady=5)
            
            open_button = tk.Button(button_frame, text="Open",
                                  command=lambda: open_file(file_path),
                                  width=15)
            open_button.pack(side="left", padx=5)
            
            save_button = tk.Button(button_frame, text="Save as...",
                                  command=lambda: save_file_as(file_path),
                                  width=15)
            save_button.pack(side="left", padx=5)
            
            user1_file_frame.pack(pady=5, anchor="e")

            # Display encrypted file on User 2's side (receiver)
            user2_file_frame = tk.Frame(user2_frame, bg='red', padx=10, pady=5, relief="solid", bd=2)

            # Create a frame for the file info to allow for bullet point
            file_info_frame = tk.Frame(user2_file_frame, bg='red')
            file_info_frame.pack(fill="x", padx=5, pady=5)
            
            # Add bullet point
            bullet = tk.Label(file_info_frame, text="•", bg='red', fg='white')
            bullet.pack(side="left", padx=(0,5))
            
            # Calculate file size
            file_size = os.path.getsize(encrypted_path)
            file_size_kb = file_size / 1024  # Convert to KB
            
            # Show file info with size and type
            file_info = f"{original_filename}.enc\n{file_size_kb:.1f} KB, ENC File"
            
            encrypted_label = tk.Label(file_info_frame, 
                                 text=file_info,
                                 bg='red',
                                 fg='white',
                                 justify="left",
                                 wraplength=250)
            encrypted_label.pack(side="left", fill="x")
            
            # Add View Encrypted File button
            view_button = tk.Button(user2_file_frame, text="Decrypt File",
                                   command=lambda: view_encrypted_file(encrypted_data, encrypted_label))
            view_button.pack(pady=5)
            
            user2_file_frame.pack(pady=5, anchor="w")
            
            key_popup.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    submit_button = tk.Button(key_popup, text="Submit", command=send_file)
    submit_button.pack(pady=10)

def upload_and_encrypt_user2():
    file_path = file_path_var2.get()  # Use the path from the entry
    if not file_path:
        return

    key_popup = tk.Toplevel()
    key_popup.title("Enter Encryption Key")
    key_popup.geometry("300x200")
    
    key_var = tk.StringVar()
    
    def generate_key():
        key = generate_combined_key()
        key_var.set(key.hex())
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key.hex())
    
    generate_button = tk.Button(key_popup, text="Generate Key", command=generate_key)
    generate_button.pack(pady=10)
    
    key_entry = tk.Entry(key_popup, width=40, textvariable=key_var)
    key_entry.pack(pady=5)
    
    def process_encryption():
        key = key_var.get()
        if not key:
            messagebox.showerror("Error", "Please generate a key first")
            return

        try:
            # Convert hex string back to bytes
            key_bytes = bytes.fromhex(key)
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = aes_cbc_encrypt(file_data, key_bytes)
            
            # Save encrypted file
            encrypted_folder = "encrypted_files"
            if not os.path.exists(encrypted_folder):
                os.makedirs(encrypted_folder)
            
            original_filename = os.path.basename(file_path)
            encrypted_path = os.path.join(encrypted_folder, original_filename + ".enc")
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
                f.flush()
                os.fsync(f.fileno())
            
            # Get file info
            file_size = os.path.getsize(file_path)
            file_size_kb = file_size / 1024
            file_type = os.path.splitext(original_filename)[1][1:].upper()
            
            # Display file info with Open and Save as buttons
            file_frame = display_file_info_user2(original_filename, file_size_kb, file_type, encrypted_data)
            
            # Display encrypted file on User 1's side (receiver)
            user1_file_frame = tk.Frame(user1_frame, bg='red', padx=10, pady=5, relief="solid", bd=2)

            # Create a frame for the file info to allow for bullet point
            file_info_frame = tk.Frame(user1_file_frame, bg='red')
            file_info_frame.pack(fill="x", padx=5, pady=5)
            
            # Add bullet point
            bullet = tk.Label(file_info_frame, text="•", bg='red', fg='white')
            bullet.pack(side="left", padx=(0,5))
            
            # Calculate file size
            file_size = os.path.getsize(encrypted_path)
            file_size_kb = file_size / 1024  # Convert to KB
            
            # Show file info with size and type
            file_info = f"{original_filename}.enc\n{file_size_kb:.1f} KB, ENC File"
            
            encrypted_label = tk.Label(file_info_frame, 
                                 text=file_info,
                                 bg='red',
                                 fg='white',
                                 justify="left",
                                 wraplength=250)
            encrypted_label.pack(side="left", fill="x")
            
            # Add View Encrypted File button
            view_button = tk.Button(user1_file_frame, text="Decrypt File File",
                                   command=lambda: view_encrypted_file(encrypted_data, encrypted_label))
            view_button.pack(pady=5)
            
            user1_file_frame.pack(pady=5, anchor="w")
            
            key_popup.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            key_popup.destroy()
    
    process_button = tk.Button(key_popup, text="Submit", command=process_encryption)
    process_button.pack(pady=20)

def create_ui():
    global root, user1_frame, user2_frame
    root = tk.Tk()
    root.title("Secure File Transfer System")
    root.geometry("800x500")

    # Create main container
    main_frame = tk.Frame(root)
    main_frame.pack(fill="both", expand=True)

    # Load background image
    bg_image = Image.open("images/kk.jpg")  # Using your existing background image

    # Create User 1 frame
    user1_frame = tk.Frame(main_frame)
    user1_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
    
    # Create User 2 frame
    user2_frame = tk.Frame(main_frame)
    user2_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

    # Configure grid weights
    main_frame.grid_columnconfigure(0, weight=1)
    main_frame.grid_columnconfigure(1, weight=1)
    main_frame.grid_rowconfigure(0, weight=1)

    # Resize and set background for User 1
    user1_bg_image = bg_image.resize((400, 600))
    user1_bg = ImageTk.PhotoImage(user1_bg_image)
    
    user1_bg_label = tk.Label(user1_frame, image=user1_bg)
    user1_bg_label.image = user1_bg
    user1_bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    # Resize and set background for User 2
    user2_bg_image = bg_image.resize((400, 600))
    user2_bg = ImageTk.PhotoImage(user2_bg_image)
    
    user2_bg_label = tk.Label(user2_frame, image=user2_bg)
    user2_bg_label.image = user2_bg
    user2_bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    # Create title labels without frames, directly on background
    user1_label = tk.Label(user1_frame, text="USER 1", font=("Arial", 16, "bold"), 
                          bg='#000033', fg='White')  # Dark blue background to match image
    user1_label.pack(pady=10)

    user2_label = tk.Label(user2_frame, text="USER 2", font=("Arial", 16, "bold"), 
                          bg='#000033', fg='white')  # Dark blue background to match image
    user2_label.pack(pady=10)

    # Bottom section for User 1
    bottom_frame_user1 = tk.Frame(user1_frame, bg='white')
    bottom_frame_user1.pack(fill="x", padx=10, pady=10, side="bottom")

    # File selection frame for User 1
    file_select_frame1 = tk.Frame(bottom_frame_user1, bg='white')
    file_select_frame1.pack(fill="x", pady=5)
    
    # Add entry field for file path
    global file_path_var
    file_path_var = tk.StringVar()
    file_path_entry1 = tk.Entry(file_select_frame1, textvariable=file_path_var, width=40)
    file_path_entry1.pack(side="left", padx=5, fill="x", expand=True)
    
    # Add Browse button
    browse_button1 = tk.Button(file_select_frame1, text="Browse", 
                              command=lambda: browse_file(file_path_var))
    browse_button1.pack(side="left", padx=5)

    # Upload Button for User 1
    upload_button1 = tk.Button(bottom_frame_user1, text="Upload File", 
                              command=upload_and_encrypt_user1)
    upload_button1.pack(pady=5)

    # Bottom section for User 2
    bottom_frame_user2 = tk.Frame(user2_frame, bg='white')
    bottom_frame_user2.pack(fill="x", padx=10, pady=10, side="bottom")

    # File selection frame for User 2
    file_select_frame2 = tk.Frame(bottom_frame_user2, bg='white')
    file_select_frame2.pack(fill="x", pady=5)
    
    # Add entry field for file path
    global file_path_var2
    file_path_var2 = tk.StringVar()
    file_path_entry2 = tk.Entry(file_select_frame2, textvariable=file_path_var2, width=40)
    file_path_entry2.pack(side="left", padx=5, fill="x", expand=True)
    
    # Add Browse button
    browse_button2 = tk.Button(file_select_frame2, text="Browse", 
                              command=lambda: browse_file(file_path_var2))
    browse_button2.pack(side="left", padx=5)

    # Upload Button for User 2
    upload_button2 = tk.Button(bottom_frame_user2, text="Upload File", 
                              command=upload_and_encrypt_user2)
    upload_button2.pack(pady=5)

    # Helper function for browse button
    def browse_file(path_var):
        filename = filedialog.askopenfilename()
        if filename:
            path_var.set(filename)

def save_file_as(original_file):
    """Save file with a new name"""
    try:
        file_name = os.path.basename(original_file)
        save_path = filedialog.asksaveasfilename(
            defaultextension=os.path.splitext(file_name)[1],
            initialfile=file_name,
            filetypes=[("All Files", "*.*")]
        )
        if save_path:
            with open(original_file, 'rb') as src, open(save_path, 'wb') as dst:
                dst.write(src.read())
    except Exception as e:
        messagebox.showerror("Error", f"Could not save file: {str(e)}")

if __name__ == "__main__":
    create_ui()
    root.mainloop()  # Move mainloop() to after create_ui() 