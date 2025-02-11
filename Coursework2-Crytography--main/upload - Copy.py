import tkinter as tk
from tkinter import filedialog
import subprocess

def browse_file(entry):
    file_path = filedialog.askopenfilename()
    if file_path:
        entry.delete(0, tk.END)
        entry.insert(0, file_path)

def open_encryption(file_path, window):
    """Pass the file path to project.py (Encryption UI)"""
    if file_path:
        window.destroy()
        subprocess.Popen(["python", "project.py", file_path])

def file_upload_ui():
    upload_window = tk.Tk()
    upload_window.title("Secure File Transfer System - Upload")
    upload_window.geometry("500x300")

    tk.Label(upload_window, text="Secure File Transfer System", font=("Arial", 16, "bold")).pack(pady=10)
    tk.Label(upload_window, text="File Uploading Process", font=("Arial", 12)).pack(pady=5)

    frame = tk.Frame(upload_window)
    frame.pack(pady=10, padx=10)

    tk.Label(frame, text="Choose a file:").grid(row=0, column=0, padx=5, pady=5)
    file_entry = tk.Entry(frame, width=40)
    file_entry.grid(row=0, column=1, padx=5, pady=5)

    tk.Button(frame, text="Browse", command=lambda: browse_file(file_entry)).grid(row=0, column=2, padx=5, pady=5)

    tk.Button(upload_window, text="Next", width=10, command=lambda: open_encryption(file_entry.get(), upload_window)).pack(pady=10)

    upload_window.mainloop()

if __name__ == "__main__":
    file_upload_ui()
