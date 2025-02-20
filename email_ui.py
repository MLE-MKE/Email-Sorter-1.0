import tkinter as tk
from tkinter import scrolledtext

def display_emails(sorted_emails):
    window = tk.Tk()
    window.title("Sorted Emails")
    
    text_area = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=100, height=30)
    text_area.pack(padx=10, pady=10)
    
    for email_info in sorted_emails:
        subject = email_info["subject"]
        from_ = email_info["from"]
        category = email_info["category"]
        text_area.insert(tk.END, "Subject: {}\nFrom: {}\nCategory: {}\n{}\n".format(
            subject, from_, category, "-" * 40))
    
    window.mainloop()
