# 🔐 Secure Password Manager

> **One Line Description:**
> A highly secure, encrypted password vault application that safely stores, generates, analyzes, and manages user credentials using modern cybersecurity techniques.

# 🧾 Project Overview

## 📌 Project Name

**Secure Password Manager**

## 👨‍💻 Developed By

**Syed Shaheer Hussain**
© Copyright 2026

# 🌍 Introduction

In today's digital world, users maintain dozens or even hundreds of online accounts. Managing these credentials manually is risky and inefficient. Many people reuse passwords or store them insecurely, making them vulnerable to cyber attacks.

The **Secure Password Manager** is designed to eliminate these risks by providing a **centralized, encrypted vault** where users can safely store and manage credentials.

This project applies real cybersecurity concepts including:

* Hashing
* Encryption
* Secure authentication
* Password strength evaluation
* Vault locking mechanisms

## Screenshots

![Screenshots](https://github.com/SyedShaheerHussain/Secure-Password-Manager-GUI-Python/blob/d774c57ab59ece76e94d79118d98eb470fc3c514/secure%20password%20manager/Screenshots/SPM.gif)

# 🎯 Mission

To build a secure, user-friendly password management system that protects user credentials from unauthorized access, cyber threats, and data breaches.

# 🧠 Objectives

1. Provide encrypted password storage
2. Prevent plaintext credential storage
3. Implement secure authentication
4. Promote strong password practices
5. Apply real-world cybersecurity concepts
6. Provide easy GUI-based interaction
7. Demonstrate secure application architecture

# ❓ Why Secure Password Manager Was Made

## 🚨 Problems in Market

* Users reuse passwords
* Weak password selection
* Passwords stored in browsers or notes
* Frequent data breaches
* Lack of encryption awareness

## ✅ Solution Provided

This system:

* Encrypts stored passwords
* Hashes master passwords
* Provides secure vault access
* Generates strong passwords
* Prevents credential leaks

# 💰 Market Value

Password managers are widely used in cybersecurity industries because:

* Increasing cybercrime
* Growing number of digital accounts
* Regulatory compliance requirements
* Rising demand for data privacy

# 🛠 Technologies Used

## 🧑‍💻 Programming Language

* Python

## 🔐 Cryptography

* AES-256 Encryption
* Bcrypt Hashing
* PBKDF2-HMAC Key Derivation

## 🗄 Database

* SQLite

## 🖥 GUI Framework

* Tkinter / CustomTkinter

## 🧰 Development Tools

* Visual Studio Code
* Python Interpreter
* Windows OS

# 🏗 System Architecture

```
User Interface (GUI)
        ↓
Application Logic
        ↓
Security Layer
(Hashing + Encryption)
        ↓
Database Layer (SQLite)

```
# 📂 Folder Structure

```
Secure Password Manager/
│
├── main.py
├── database.py
├── security.py
├── crypto_utils.py
├── config.py
├── secure_password_manager.db
└── backups/

```

# 🧩 Codes Files Explanation

## 📌 main.py

### Purpose:

Controls GUI and application flow.

### Functions:

* Login handling
* Signup screen
* Dashboard navigation
* Vault unlocking
* Password CRUD operations

## 📌 database.py

### Purpose:

Handles database operations.

### Functions:

* Create user
* Store passwords
* Retrieve encrypted data
* Update credentials
* Delete entries

## 📌 security.py

### Purpose:

Handles authentication security.

### Functions:

* Password hashing using bcrypt
* Password verification

## 📌 crypto_utils.py

### Purpose:

Handles encryption and password generation.

### Functions:

* AES encryption
* AES decryption
* Password generator
* Strength analyzer
* Key derivation

## 📌 config.py

### Purpose:

Application configuration settings.

Contains:

* App dimensions
* Auto lock timer
* Clipboard timeout
* Backup directories

# 🔐 Core Security Features

## 1️⃣ Secure User Authentication

* Master password hashing
* Salt generation
* Bcrypt verification

## 2️⃣ AES-256 Encryption

Stored credentials encrypted before database storage.

## 3️⃣ Vault Unlock Mechanism

Second security layer requiring master password.

## 4️⃣ Password Generator

Generates random strong passwords using secure algorithms.

## 5️⃣ Password Strength Checker

Evaluates complexity based on:

* Length
* Symbols
* Numbers
* Uppercase
* Lowercase

## 6️⃣ Auto Lock Feature

Locks vault after inactivity.

## 7️⃣ Clipboard Protection

Automatically clears copied passwords.

## 8️⃣ Backup System

Encrypted password backups.

# 🖥 GUI Features

## Screens Included:

### 🔑 Signup Screen

User registration with secure password hashing.

### 🔐 Login Screen

Secure authentication system.

### 🧰 Vault Unlock Screen

Decrypts stored vault using master password.

### 📊 Dashboard

Main control center.

### ➕ Add Password Screen

Stores new credentials.

### 🔍 View/Search Screen

Search and retrieve stored passwords.

### 🎲 Password Generator

Generate strong credentials.

### ⚙ Settings Screen

Theme and application options.

# ⚙ Working of System

## Step 1: User Signup

* Email entered
* Master password hashed
* Data stored securely

## Step 2: Login

* Password verified using bcrypt

## Step 3: Vault Unlock

* AES key derived
* Vault decrypted

## Step 4: Add Password

* Credentials encrypted
* Stored in database

## Step 5: Retrieval

* Password decrypted in memory only

# ▶ Installation Guide

## 🧾 Requirements

* Python 3.9+
* pip installed

## 📦 Install Dependencies

```bash
pip install bcrypt cryptography customtkinter

```
# ▶ Running The Project

## Step-By-Step

### Step 1

Open project folder

### Step 2

Run command:

```bash
python main.py

```

# 🌐 Run in Chrome (If Hosted)

### Step 1

Host using Flask or local server

### Step 2

Open Chrome

### Step 3

Go to:

```
http://localhost:5000

```

### Default Login (If Demo Mode Exists)

```
Username: admin@example.com
Password: Admin@123

```

# 📊 Flow Chart

```
Start
  ↓
Signup/Login
  ↓
Vault Unlock
  ↓
Dashboard
  ↓
Manage Passwords
  ↓
Auto Lock / Logout
  ↓
End

```

# 🧪 Concepts Learned

* Cryptography implementation
* Secure authentication design
* Database security
* GUI development
* Password lifecycle management
* Secure coding practices

# ✅ Advantages

* Strong encryption
* Local data security
* User-friendly interface
* Prevents credential leaks
* Open-source customization

# ❌ Disadvantages

* Local storage only
* No cloud sync
* Single device limitation

# 🔮 Future Enhancements

* Cloud synchronization
* Mobile application
* Biometric authentication
* Multi-user support
* Hardware security modules
* Browser extension

# 🔍 How This Protects From Phishing & Breaches

### Detects Unsafe Practices:

* Weak password alerts
* Reuse prevention
* Secure storage prevents leaks

### Helps Users Stay Safe:

* Generates secure passwords
* Prevents credential reuse
* Encrypts sensitive data

# ⚠ Cautions

>[!caution]
> * Never share master password
> * Backup encrypted files regularly
> * Avoid installing from untrusted sources

# ❗ Important Notes

>[!important]
> * Passwords cannot be recovered if master password is lost
> * Always use strong master password

# 📜 Disclaimer

>[!warning]
> This project is developed for educational and cybersecurity awareness purposes only. The developers are not responsible for misuse or loss of credentials.

# 📖 Usage Guide

### How To Use

1. Signup account
2. Login securely
3. Unlock vault
4. Add credentials
5. Generate passwords
6. Search stored passwords
7. Logout safely

# 🧭 When To Use

* Managing multiple accounts
* Storing sensitive credentials
* Creating strong passwords

# 📍 Where To Use

* Personal systems
* Small business credential management
* Educational cybersecurity demonstrations

# 🏷 Tags

```
Cybersecurity
Password Manager
Encryption
AES256
Bcrypt
Authentication
Secure Storage
Python Security
Cryptography

```
# 📄 License

>[!note]
> Copyright © 2026
> Developed by **Syed Shaheer Hussain**

**All Rights Reserved.**
