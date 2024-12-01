import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from socket import socket, AF_INET, SOCK_STREAM
from base64 import b64encode
import ssl
import ttkbootstrap as tb

def attach_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        attachments.append(file_path)
        attachment_list.insert(tk.END, file_path)

def send_email():
    SenderEmail = email_entry.get()
    SenderPassword = password_entry.get()
    ReceiverEmail = receiver_entry.get()
    Subject = subject_entry.get()
    EmailBody = body_entry.get("1.0", tk.END).strip()

    if not SenderEmail:
        messagebox.showerror("Error", "Please enter your email address.")
        return
    if not SenderPassword:
        messagebox.showerror("Error", "Please enter your password.")
        return
    if not ReceiverEmail:
        messagebox.showerror("Error", "Please enter the receiver's email address.")
        return
    if not Subject:
        messagebox.showerror("Error", "Please enter the email subject.")
        return
    if not EmailBody:
        messagebox.showerror("Error", "Please enter the email body message.")
        return

    msg = '{}\r\n'.format(EmailBody)
    endmsg = '\r\n.\r\n'

    mailServer = 'smtp.gmail.com'
    mailPort = 587

    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((mailServer, mailPort))
    confMsg = clientSocket.recv(1024).decode()
    print(confMsg)
    if confMsg[:3] != '220':
        raise Exception("220 reply not received from server.")

    heloCommand = 'HELO Alice\r\n'
    clientSocket.send(heloCommand.encode())
    recv1 = clientSocket.recv(1024).decode()
    print(recv1)
    if recv1[:3] != '250':
        raise Exception("250 reply not received from server.")

    strtlscmd = "STARTTLS\r\n"
    clientSocket.send(strtlscmd.encode())
    confMsg2 = clientSocket.recv(1024).decode()
    print(confMsg2)
    if confMsg2[:3] != '220':
        raise Exception("220 reply not received after STARTTLS.")

    context = ssl.create_default_context()
    sslClientSocket = context.wrap_socket(clientSocket, server_hostname=mailServer)

    EMAIL_ADDRESS = b64encode(SenderEmail.encode()).decode()
    EMAIL_PASSWORD = b64encode(SenderPassword.encode()).decode()

    sslClientSocket.send("AUTH LOGIN\r\n".encode())
    confMsg3 = sslClientSocket.recv(1024).decode()
    print(confMsg3)

    sslClientSocket.send((EMAIL_ADDRESS + "\r\n").encode())
    confMsg4 = sslClientSocket.recv(1024).decode()
    print(confMsg4)

    sslClientSocket.send((EMAIL_PASSWORD + "\r\n").encode())
    confMsg5 = sslClientSocket.recv(1024).decode()
    print(confMsg5)

    mailfrom = f"MAIL FROM: <{SenderEmail}>\r\n"
    sslClientSocket.send(mailfrom.encode())
    confMsg6 = sslClientSocket.recv(1024).decode()
    print(confMsg6)

    rcptto = f"RCPT TO: <{ReceiverEmail}>\r\n"
    sslClientSocket.send(rcptto.encode())
    confMsg7 = sslClientSocket.recv(1024).decode()
    print(confMsg7)

    sslClientSocket.send("DATA\r\n".encode())
    confMsg8 = sslClientSocket.recv(1024).decode()
    print(confMsg8)

    boundary = "----=_NextPart_000_0000_01D3_2A2A"
    message = f"Subject: {Subject}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n"
    message += f"--{boundary}\r\nContent-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n{msg}\r\n"

    for file_path in attachments:
        with open(file_path, "rb") as f:
            file_data = f.read()
            encoded_file = b64encode(file_data).decode()
            filename = file_path.split('/')[-1]
            message += f"--{boundary}\r\nContent-Type: application/octet-stream; name=\"{filename}\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\n\r\n{encoded_file}\r\n\r\n"

    message += f"--{boundary}--\r\n"
    sslClientSocket.send(message.encode())

    sslClientSocket.send(endmsg.encode())
    confMsg9 = sslClientSocket.recv(1024).decode()
    print(confMsg9)

    sslClientSocket.send("QUIT\r\n".encode())
    confMsg10 = sslClientSocket.recv(1024).decode()
    print(confMsg10)

    sslClientSocket.close()
    messagebox.showinfo("Success", "Email sent successfully!")

    email_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    receiver_entry.delete(0, tk.END)
    subject_entry.delete(0, tk.END)
    body_entry.delete("1.0", tk.END)
    attachment_list.delete(0, tk.END)
    attachments.clear()

root = tb.Window(themename="superhero")
root.title("SMTP Email Sender")
root.geometry("500x500")

root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=3)
root.grid_rowconfigure(4, weight=1)
root.grid_rowconfigure(5, weight=1)

style = ttk.Style()
style.configure("TLabel", font=("Helvetica", 10))
style.configure("TButton", font=("Helvetica", 10, "bold"), foreground="white", background="#007bff", relief="solid", bordercolor="#007bff", borderwidth=2, focusthickness=3, focuscolor="none", padding=10)
style.configure("TEntry", font=("Helvetica", 10), fieldbackground="#e0f7fa", foreground="#007bff")

entry_width = 40

ttk.Label(root, text="Your Email Address:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
email_entry = ttk.Entry(root, width=entry_width, style="TEntry")
email_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

ttk.Label(root, text="Your Password:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
password_entry = ttk.Entry(root, show="*", width=entry_width, style="TEntry")
password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

ttk.Label(root, text="Email Destination:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
receiver_entry = ttk.Entry(root, width=entry_width, style="TEntry")
receiver_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

ttk.Label(root, text="Email Subject:").grid(row=3, column=0, padx=10, pady=5, sticky="e")
subject_entry = ttk.Entry(root, width=entry_width, style="TEntry")
subject_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

ttk.Label(root, text="Email Body Message:").grid(row=4, column=0, padx=10, pady=5, sticky="ne")
body_entry = tk.Text(root, height=10, width=entry_width, font=("Helvetica", 10), bg="#e0f7fa", fg="#007bff")
body_entry.grid(row=4, column=1, padx=10, pady=5, sticky="nsew")

ttk.Label(root, text="Attachments:").grid(row=5, column=0, padx=10, pady=5, sticky="ne")
attachment_list = tk.Listbox(root, height=5, width=entry_width, font=("Helvetica", 10), borderwidth=1, relief="solid", bg="#e0f7fa", fg="#007bff")
attachment_list.grid(row=5, column=1, padx=10, pady=5, sticky="nsew")

attach_button = tb.Button(root, text="Attach File", command=attach_file, bootstyle="primary-outline", style="TButton")
attach_button.grid(row=6, column=1, padx=10, pady=10, sticky="e")

send_button = tb.Button(root, text="Send Email", command=send_email, bootstyle="success-outline", style="TButton")
send_button.grid(row=7, column=1, padx=10, pady=10, sticky="e")

attachments = []

root.mainloop()
