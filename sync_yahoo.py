import imaplib
import email
from email.header import decode_header
from email_ui import display_emails  # Import the UI function

# Your Yahoo email credentials
username = "email"
password = "password"

def sort_email(subject):
    # Define the sorting rules with multiple keywords per category.
    rules = {
        'Receipts': ['receipt', 'order', 'purchase'],   # All purchase/receipt emails
        'Work': ['meeting', 'project', 'deadline'],       # Work-related emails
        'Finance': ['invoice'],                           # Finance emails (e.g., invoices)
        'Promotions': ['offer', 'sale', 'coupon']         # Promotional emails
    }
    
    subject_lower = subject.lower()  # Convert subject to lowercase for comparison.
    
    # Loop through each category and its list of keywords.
    for category, keywords in rules.items():
        for keyword in keywords:
            if keyword in subject_lower:
                return category  # Return the category as soon as a match is found.
    
    # If no keywords match, return 'Misc'
    return 'Misc'

# Connect to the Yahoo IMAP server
mail = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
sorted_emails = []  # List to store email details

try:
    # Log in to your Yahoo account
    mail.login(username, password)
    print("Login successful!")
    
    # Select the mailbox you want to check (INBOX is default)
    mail.select("inbox")

    # Search for all emails in the inbox
    status, messages = mail.search(None, "ALL")
    email_ids = messages[0].split()

    # Process the most recent email (or loop through all if desired)
    if email_ids:
        latest_email_id = email_ids[-1]  # Get the ID of the most recent email
        status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
        
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                # Parse the email content
                msg = email.message_from_bytes(response_part[1])
      
                # Decode the subject and sender
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                from_ = msg.get("From")
                
                # Call the sorting function
                category = sort_email(subject)
                
                # Print to the terminal (optional)
                print("Subject: %s" % subject)
                print("From: %s" % from_)
                print("Category: %s" % category)
                print("-" * 40)
                
                # Store the details in the list
                sorted_emails.append({
                    "subject": subject,
                    "from": from_,
                    "category": category
                })
    else:
        print("No emails found.")

except Exception as e:
    print("An error occurred: %s" % e)
finally:
    mail.logout()

# Now, call the UI function to display the sorted emails in a new window.
if sorted_emails:
    display_emails(sorted_emails)
