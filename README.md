# Titan Encryption Tool

![Titan Encryption Tool](https://img.shields.io/badge/Version-1.0.0-blue.svg) ![License](https://img.shields.io/badge/License-Proprietary-lightgrey.svg) ![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)

A secure desktop application for file encryption/decryption with collaboration features, built with modern cryptographic techniques.

## ✨ Features

- **🔒 Secure Encryption**: NaCl SecretBox implementation with 256-bit keys
- **👥 User Management**: Secure authentication with Argon2id hashing
- **🗂️ Key Management**: Organized storage and management of encryption keys
- **🤝 Collaboration**: Real-time chat and secure file sharing
- **👮 Admin Panel**: User management and server monitoring
- **📊 System Monitoring**: Real-time CPU/VRAM tracking with Trinity Engine
- **🔐 Security Protocols**: File locking after failed attempts and key termination

## 📋 Requirements

- **Operating System**: Windows 10/11, macOS 11+, or Linux (Ubuntu 20.04+)
- **Python**: 3.10 or higher
- **RAM**: Minimum 4 GB (8 GB recommended)
- **Disk Space**: 500 MB free space

## 🚀 Installation

1. **Clone or download the application**
   ```bash
   # If using git
   git clone <repository-url>
   cd titan-encryption-tool
   ```

2. **Install required dependencies**
   ```bash
   pip install customtkinter pynacl psutil matplotlib pillow pyperclip
   ```

3. **Run the application**
   ```bash
   python titan.py
   ```

## 🎯 Usage

### First Time Setup
1. Launch the application
2. Register a new account or use the default admin credentials:
   - Username: `Admin`
   - Password: `Admin123`

### Encrypting Files
1. Navigate to the **Tools** tab
2. Select **Encrypt** mode
3. Browse and select your file
4. The application will generate and store an encryption key automatically
5. Your file will be encrypted with a `.titan` extension

### Decrypting Files
1. Navigate to the **Tools** tab
2. Select **Decrypt** mode
3. Browse and select your `.titan` file
4. Paste the encryption key (or select from Key Manager)
5. The file will be decrypted with `_decrypted` added to the filename

### Collaboration Features
1. Admins can create collaboration servers from the **Admin Panel**
2. Users can join servers from the **Collaboration** tab
3. Share files and chat with other connected users in real-time

## 🏗️ Architecture

### Cryptographic Implementation
- Encryption: NaCl SecretBox (XSalsa20-Poly1305)
- Key Derivation: Argon2id
- Key Size: 32 bytes (256-bit)
- File Format: Custom `.titan` format with metadata support

### Database Schema
- SQLite database (`titan.db`)
- Users table: Authentication and user information
- Keys table: Encryption keys and metadata

## 📁 Project Structure

```
titan-encryption-tool/
├── titan.py              # Main application file
├── titan.db             # Database file (created after first run)
├── collab_sessions.json # Collaboration sessions data
└── titan_errors.log     # Application error logging
```

## 🔧 Technical Details

### Security Features
- Three-strike decryption policy (files become permanently locked after 3 failed attempts)
- Key termination capability
- User banning system
- Secure password hashing with Argon2id

### Performance
- Stream encryption/decryption for large files
- Threaded operations for responsive UI
- Efficient memory management

## 👥 User Management

### Default Admin Account
- Username: `Admin`
- Password: `Admin123`

### Admin Capabilities
- Create and manage collaboration servers
- View all users and their status
- Ban/unban users
- Promote/demote user privileges

## 🤝 Collaboration System

### Server Creation
1. Admins can create servers with unique IDs and ports
2. Servers can be started, stopped, or terminated
3. Real-time user joining/leaving notifications

### File Sharing
1. Users can share files within collaboration sessions
2. Shared files are accessible to all connected users
3. Download tracking and management

## ⚠️ Troubleshooting

### Common Issues
1. **Application fails to start**
   - Ensure all dependencies are installed correctly
   - Verify Python version is 3.10+

2. **Cannot join collaboration server**
   - Verify server ID and port are correct
   - Ensure the server is running

3. **Decryption failures**
   - Verify you're using the correct key
   - Check that the file hasn't been locked due to failed attempts

### Getting Help
For additional support:
- Email: rohandhananjaymaske@gmail.com

## 📄 License

Titan Encryption Tool is proprietary software. See the License Agreement within the application for complete terms.

## 🔒 Privacy

Your privacy is important to us. Please review the Privacy Policy within the application for details on data collection and usage.

---

**Note**: This application is designed for secure file encryption. Always maintain backups of your encryption keys, as lost keys will result in permanent data loss.
