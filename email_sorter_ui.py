import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import imaplib
import email
from email.header import decode_header
import webbrowser

class EmailSorterApp:
    def __init__(self, master):
        self.master = master
        master.title("Email Sorter App")
        
        #peepeepoopoo I can not believe i didnt commit or push for 6 whole hours
        #I  mean I can because I did and thats like what we all do right? 
        #someone lie to me and say its fine that there are no branches to this. 
        #anywasy stay tuned for the fixed 2.0 version with better or even customizable ui
        
        
        #  ------ To Do -----
        # -- 1. add a drop down customizable UI 
        # -- background
        # -- Text?
        # -- Color 
        
        # -- 2.
        # ---------- Login Frame (shown initially) ----------
        self.login_frame = tk.Frame(master)
        self.login_frame.pack(pady=20)
        
        tk.Label(self.login_frame, text="Email:").grid(row=0, column=0, sticky="e")
        tk.Label(self.login_frame, text="App Password:").grid(row=1, column=0, sticky="e")
        
        self.username_entry = tk.Entry(self.login_frame, width=30)
        self.password_entry = tk.Entry(self.login_frame, width=30, show="*")
        self.username_entry.grid(row=0, column=1, padx=5)
        self.password_entry.grid(row=1, column=1, padx=5)
        
        # Link for "How to create app password"
        self.app_password_link = tk.Label(self.login_frame, text="How to create app password", fg="blue", cursor="hand2")
        self.app_password_link.grid(row=2, column=1, sticky="w", padx=5, pady=(0,10))
        self.app_password_link.bind("<Button-1>", lambda e: self.open_link("https://support.google.com/mail/answer/185833?hl=en"))
        
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=3, column=0, columnspan=2, pady=10)
        
        # ---------- Main Frame (hidden until login) ----------
        self.main_frame = tk.Frame(master)
        # Not packed initially; will be shown after successful login
        
        # --- Rule Editor Frame ---
        self.rule_editor_frame = tk.Frame(self.main_frame)
        self.rule_editor_frame.pack(pady=10)
        
        tk.Label(self.rule_editor_frame, text="Add Email Category").grid(row=0, column=0, columnspan=2)
        tk.Label(self.rule_editor_frame, text="Category:").grid(row=1, column=0, sticky="e")
        tk.Label(self.rule_editor_frame, text="Phrases (comma-separated):").grid(row=2, column=0, sticky="e")
        
        self.category_entry = tk.Entry(self.rule_editor_frame, width=20)
        self.phrases_entry = tk.Entry(self.rule_editor_frame, width=40)
        self.category_entry.grid(row=1, column=1, padx=5)
        self.phrases_entry.grid(row=2, column=1, padx=5)
        
        self.add_rule_button = tk.Button(self.rule_editor_frame, text="Add Category", command=self.add_rule)
        self.add_rule_button.grid(row=3, column=0, columnspan=2, pady=5)
        
        tk.Label(self.rule_editor_frame, text="Current Categories:").grid(row=4, column=0, columnspan=2)
        self.rules_listbox = tk.Listbox(self.rule_editor_frame, width=60)
        self.rules_listbox.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        # Bind double-click event to allow editing a category (adding keywords)
        self.rules_listbox.bind("<Double-Button-1>", self.edit_category)
        
        self.delete_rule_button = tk.Button(self.rule_editor_frame, text="Delete Category", command=self.delete_rule)
        self.delete_rule_button.grid(row=6, column=0, columnspan=2, pady=5)
        
        # --- Actions Frame ---
        self.action_frame = tk.Frame(self.main_frame)
        self.action_frame.pack(pady=10)
        
        self.fetch_button = tk.Button(self.action_frame, text="Fetch & Sort Emails", command=self.fetch_emails, state="disabled")
        self.fetch_button.pack()
        
        self.suggest_button = tk.Button(self.action_frame, text="Suggest Categories", command=self.suggest_categories, state="disabled")
        self.suggest_button.pack(pady=5)
        
        # --- Display Frame (for sorted emails) ---
        self.display_frame = tk.Frame(self.main_frame)
        # This frame is not packed until emails are fetched.
        tk.Label(self.display_frame, text="Sorted Emails by Category:").pack()
        self.email_tree = ttk.Treeview(self.display_frame)
        self.email_tree.pack(fill="both", expand=True)
        
        # ---------- Other Variables ----------
        self.mail = None  # IMAP connection variable
        # Dictionary to store rules as: { "Category": ["phrase1", "phrase2", ...], ... }
        self.sorting_rules = {}
        
        # Load some default rules (optional)
        self.default_rules = {
          'Security': ['password', 'reset', 'verify', 'authentication', 'login', 'secure', 'account', 'update', 'access', 'locked'],  # Security-related emails (e.g., password reset, account verification)

            'Work': ['request', 'ready', 'please', 'project', 'deadline', 'meeting', 'proposal', 'assignment', 'team', 'submission',
            'appointment', 'calendar', 'event', 'reminder', 'conference', 'available'],  # Work-related emails (e.g., schedules, meetings, tasks)

            'Receipts/Finances': ['paid', 'invoice', 'receipt', 'transaction', 'payment', 'balance', 'refund', 'statement', 'order', 'subscription'],  # Financial emails (e.g., payment confirmations, receipts, invoices)

            'Personal': ['ticket', 'flight', 'vacation', 'trip', 'concert', 'festival', 'cruise', 'hotel', 'reservation', 'entertainment',
             'airline', 'show', 'getaway', 'travel', 'tour'],  # Personal emails (e.g., travel, events, and fun activities)

            'Promotions': ['discount', 'coupon', 'sale', 'offer', 'promo', 'deal', 'exclusive', 'limited time', 'clearance', 'BOGO',
               'cashback', 'reward', 'gift', 'membership', 'free trial']  # Promotional emails (e.g., discounts, sales, and rewards)

        }
        self.sorting_rules.update(self.default_rules)
        self.update_rules_listbox()
    
    def open_link(self, url):
        """Open a web link in the default browser."""
        webbrowser.open_new(url)
    
    def update_rules_listbox(self):
        """Refresh the listbox to show only the current category names as bullet points."""
        self.rules_listbox.delete(0, tk.END)
        for category in self.sorting_rules.keys():
            rule_str = f"• {category}"
            self.rules_listbox.insert(tk.END, rule_str)
    
    def add_rule(self):
        """Add a new sorting rule using the Category and Phrases fields."""
        category = self.category_entry.get().strip()
        phrases = self.phrases_entry.get().strip()
        if not category or not phrases:
            messagebox.showerror("Error", "Please enter both a category and phrases.")
            return
        phrases_list = [phrase.strip() for phrase in phrases.split(",") if phrase.strip()]
        if category in self.sorting_rules:
            for phrase in phrases_list:
                if phrase not in self.sorting_rules[category]:
                    self.sorting_rules[category].append(phrase)
        else:
            self.sorting_rules[category] = phrases_list
        self.category_entry.delete(0, tk.END)
        self.phrases_entry.delete(0, tk.END)
        self.update_rules_listbox()
        messagebox.showinfo("Success", "Sorting rule added!")
    
    def delete_rule(self):
        """Delete the selected category from the sorting rules."""
        selected_indices = self.rules_listbox.curselection()
        if not selected_indices:
            messagebox.showerror("Error", "Please select a category to delete.")
            return
        selected_index = selected_indices[0]
        rule_str = self.rules_listbox.get(selected_index)
        if rule_str.startswith("• "):
            rule_str = rule_str[2:]
        category = rule_str.split(":")[0].strip()
        if category in self.sorting_rules:
            del self.sorting_rules[category]
            self.update_rules_listbox()
            messagebox.showinfo("Success", f"Category '{category}' deleted.")
        else:
            messagebox.showerror("Error", "Category not found.")
    
    def edit_category(self, event):
        """Open a pop-up window to add keywords to the selected category."""
        selected_indices = self.rules_listbox.curselection()
        if not selected_indices:
            return
        selected_index = selected_indices[0]
        rule_str = self.rules_listbox.get(selected_index)
        if rule_str.startswith("• "):
            rule_str = rule_str[2:]
        category = rule_str.split(":")[0].strip()
        edit_window = tk.Toplevel(self.master)
        edit_window.title(f"Edit Category: {category}")
        tk.Label(edit_window, text=f"Current keywords for '{category}':").pack(padx=10, pady=(10, 0))
        current_keywords = ", ".join(self.sorting_rules.get(category, []))
        tk.Label(edit_window, text=current_keywords).pack(padx=10, pady=(0, 10))
        tk.Label(edit_window, text="Add keywords (comma-separated):").pack(padx=10)
        new_keywords_entry = tk.Entry(edit_window, width=40)
        new_keywords_entry.pack(padx=10, pady=5)
        def add_keywords():
            new_keywords = new_keywords_entry.get().strip()
            if new_keywords:
                new_list = [kw.strip() for kw in new_keywords.split(",") if kw.strip()]
                for kw in new_list:
                    if kw not in self.sorting_rules[category]:
                        self.sorting_rules[category].append(kw)
                self.update_rules_listbox()
                messagebox.showinfo("Success", f"Keywords added to '{category}'.")
                edit_window.destroy()
            else:
                messagebox.showerror("Error", "Please enter at least one keyword.")
        tk.Button(edit_window, text="Add Keywords", command=add_keywords).pack(pady=10)
    
    def sort_email(self, subject):
        """Determine the category for an email based on its subject."""
        subject_lower = subject.lower()
        for category, keywords in self.sorting_rules.items():
            for keyword in keywords:
                if keyword in subject_lower:
                    return category
        return "Misc"
    
    def login(self):
        """Log in to Yahoo Mail using the credentials from the UI."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return
        try:
            self.mail = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
            
            # -- -- google imap test -- # 
            self.mail = imaplib.IMAP4_SSL("imap.gmail.com")
            
            
            
            self.mail.login(username, password)
            messagebox.showinfo("Success", "Login successful!")
            self.fetch_button.config(state="normal")
            self.suggest_button.config(state="normal")
            self.login_frame.pack_forget()
            self.main_frame.pack(pady=10, fill="both", expand=True)
        except Exception as e:
            messagebox.showerror("Login Failed", str(e))
    
    def fetch_emails(self):
        """Fetch emails from the INBOX, sort them, and display in the treeview grouped by category."""
        if not self.mail:
            messagebox.showerror("Error", "Not logged in.")
            return
        try:
            self.mail.select("inbox")
            status, messages = self.mail.search(None, "ALL")
            email_ids = messages[0].split()
            sorted_emails = []
            num_emails = 100  # Fetch 100 emails at a time
            for email_id in email_ids[-num_emails:]:
                status, msg_data = self.mail.fetch(email_id, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        subject, encoding = decode_header(msg["Subject"])[0]
                        if isinstance(subject, bytes):
                            try:
                                subject = subject.decode(encoding if encoding else "utf-8", errors='replace')
                            except LookupError:
                                subject = subject.decode("utf-8", errors='replace')
                        from_ = msg.get("From")
                        category = self.sort_email(subject)
                        sorted_emails.append({
                            "subject": subject,
                            "from": from_,
                            "category": category
                        })
            self.display_frame.pack(pady=10, fill="both", expand=True)
            self.display_emails_grouped(sorted_emails)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def display_emails_grouped(self, sorted_emails):
        """Display sorted emails in the treeview, grouped by category."""
        for item in self.email_tree.get_children():
            self.email_tree.delete(item)
        grouped = {}
        for email_info in sorted_emails:
            cat = email_info["category"]
            grouped.setdefault(cat, []).append(email_info)
        for category, emails in grouped.items():
            parent = self.email_tree.insert("", "end", text=category, open=False)
            for email_info in emails:
                item_text = f"Subject: {email_info['subject']} | From: {email_info['from']}"
                self.email_tree.insert(parent, "end", text=item_text)
    
    def suggest_categories(self):
        """Analyze email subjects from the first 100 emails and suggest categories based on common keywords.
           Displays the suggestions in a non-modal pop-up window that remains open until closed.
        """
        import string
        from collections import Counter
        import nltk
        from nltk.corpus import stopwords
        nltk.download('stopwords', quiet=True)
        stop_words = set(stopwords.words('english'))
        
        subjects = []
        try:
            self.mail.select("inbox")
            status, messages = self.mail.search(None, "ALL")
            email_ids = messages[0].split()
            num_emails = 100  # Look at the first 100 emails
            for email_id in email_ids[:num_emails]:
                status, msg_data = self.mail.fetch(email_id, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        subject, encoding = decode_header(msg["Subject"])[0]
                        if isinstance(subject, bytes):
                            try:
                                subject = subject.decode(encoding if encoding else "utf-8", errors='replace')
                            except LookupError:
                                subject = subject.decode("utf-8", errors='replace')
                        subjects.append(subject)
        except Exception as e:
            messagebox.showerror("Error", f"Error fetching email subjects: {str(e)}")
            return
        
        words = []
        for subject in subjects:
            subject_clean = subject.translate(str.maketrans("", "", string.punctuation))
            for word in subject_clean.split():
                word = word.lower()
                if word not in stop_words:
                    words.append(word)
        word_counts = Counter(words)
        common_words = word_counts.most_common(10)
        
        suggestion_text = "Suggested categories based on common keywords:\n"
        for word, count in common_words:
            suggestion_text += f"{word} (appeared {count} times)\n"
        
        suggestion_window = tk.Toplevel(self.master)
        suggestion_window.title("Category Suggestions")
        suggestion_window.geometry("400x300")
        text_area = scrolledtext.ScrolledText(suggestion_window, wrap=tk.WORD, width=50, height=15)
        text_area.pack(padx=10, pady=10)
        text_area.insert(tk.END, suggestion_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = EmailSorterApp(root)
    root.mainloop()
