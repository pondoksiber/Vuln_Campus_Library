#!/bin/bash

# Simple setup script for Campus Library

echo "Setting up Campus Library..."

# Install required packages
sudo apt update
sudo apt install -y nginx mysql-server php-fpm php-mysql php-gd

# Create project directory
sudo mkdir -p /var/www/campus-library
cd /var/www/campus-library

# Create all files directly
sudo tee config.php > /dev/null << 'EOF'
<?php
$host = 'localhost';
$dbname = 'library_db';
$username = 'root';
$password = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

session_start();
?>
EOF

# Create index.php
sudo tee index.php > /dev/null << 'EOF'
<?php
require_once 'config.php';

// Vulnerable SQL query for comments (SQL Injection vulnerability)
if (isset($_POST['comment']) && isset($_SESSION['user_id'])) {
    $book_id = $_POST['book_id'];
    $user_id = $_SESSION['user_id'];
    $comment = $_POST['comment'];
    
    // VULNERABLE: Direct SQL query without parameterization
    $sql = "INSERT INTO comments (book_id, user_id, comment) VALUES ($book_id, $user_id, '$comment')";
    $pdo->exec($sql);
}

// Fetch books
$stmt = $pdo->query("SELECT * FROM books");
$books = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Campus Library</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .navbar { background: #333; color: white; padding: 1rem; }
        .navbar a { color: white; text-decoration: none; margin: 0 1rem; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .book-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 2rem; }
        .book-card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .book-title { font-size: 1.2rem; font-weight: bold; color: #333; margin-bottom: 0.5rem; }
        .comments { margin-top: 1rem; padding: 1rem; background: #f9f9f9; border-radius: 5px; }
        .comment { padding: 0.5rem 0; border-bottom: 1px solid #eee; }
        .comment-form { margin-top: 1rem; }
        .comment-form textarea { width: 100%; padding: 0.5rem; }
        .comment-form button { margin-top: 0.5rem; padding: 0.5rem 1rem; background: #333; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <nav class="navbar">
        <a href="/">Campus Library</a>
        <?php if (isset($_SESSION['user_id'])): ?>
            <a href="/member.php">My Account</a>
            <a href="/user.php?id=<?php echo $_SESSION['user_id']; ?>">Profile</a>
            <a href="/logout.php">Logout</a>
        <?php else: ?>
            <a href="/login.php">Login</a>
        <?php endif; ?>
    </nav>

    <div class="container">
        <h1>Book Catalog</h1>
        <div class="book-grid">
            <?php foreach ($books as $book): ?>
                <div class="book-card">
                    <div class="book-title"><?php echo htmlspecialchars($book['title']); ?></div>
                    <p>Author: <?php echo htmlspecialchars($book['author']); ?></p>
                    <p>ISBN: <?php echo htmlspecialchars($book['isbn']); ?></p>
                    <p><?php echo htmlspecialchars($book['description']); ?></p>
                    
                    <div class="comments">
                        <h4>Reviews</h4>
                        <?php
                        // Fetch comments for this book
                        $comment_sql = "SELECT c.*, u.full_name FROM comments c JOIN users u ON c.user_id = u.id WHERE c.book_id = " . $book['id'];
                        $comment_stmt = $pdo->query($comment_sql);
                        $comments = $comment_stmt->fetchAll(PDO::FETCH_ASSOC);
                        
                        foreach ($comments as $comment):
                        ?>
                            <div class="comment">
                                <strong><?php echo htmlspecialchars($comment['full_name']); ?>:</strong>
                                <?php echo htmlspecialchars($comment['comment']); ?>
                            </div>
                        <?php endforeach; ?>
                        
                        <?php if (isset($_SESSION['user_id'])): ?>
                            <form method="POST" class="comment-form">
                                <input type="hidden" name="book_id" value="<?php echo $book['id']; ?>">
                                <textarea name="comment" placeholder="Add your review..." required></textarea>
                                <button type="submit">Post Review</button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
</body>
</html>
EOF

# Create other PHP files
sudo tee login.php > /dev/null << 'EOF'
<?php
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = md5($_POST['password']);
    
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    $stmt->execute([$username, $password]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        header('Location: /member.php');
        exit;
    } else {
        $error = "Invalid credentials";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login - Campus Library</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .login-container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }
        .login-container h2 { margin-bottom: 1.5rem; text-align: center; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; }
        .form-group input { width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
        .btn { width: 100%; padding: 0.75rem; background: #333; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #555; }
        .error { color: red; margin-bottom: 1rem; }
        .home-link { text-align: center; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Library Login</h2>
        <?php if (isset($error)): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
        <div class="home-link">
            <a href="/">Back to Home</a>
        </div>
    </div>
</body>
</html>
EOF

sudo tee member.php > /dev/null << 'EOF'
<?php
require_once 'config.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: /login.php');
    exit;
}

$user_id = $_SESSION['user_id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("SELECT b.*, bk.title, bk.author FROM borrowings b JOIN books bk ON b.book_id = bk.id WHERE b.user_id = ?");
$stmt->execute([$user_id]);
$borrowings = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Member Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .navbar { background: #333; color: white; padding: 1rem; }
        .navbar a { color: white; text-decoration: none; margin: 0 1rem; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .member-info { background: white; padding: 2rem; border-radius: 8px; margin-bottom: 2rem; }
        .borrowings { background: white; padding: 2rem; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; }
    </style>
</head>
<body>
    <nav class="navbar">
        <a href="/">Campus Library</a>
        <a href="/member.php">My Account</a>
        <a href="/user.php?id=<?php echo $_SESSION['user_id']; ?>">Profile</a>
        <a href="/logout.php">Logout</a>
    </nav>
    <div class="container">
        <div class="member-info">
            <h2>Welcome, <?php echo htmlspecialchars($user['full_name']); ?>!</h2>
            <p>Username: <?php echo htmlspecialchars($user['username']); ?></p>
            <p>Member since: <?php echo $user['created_at']; ?></p>
        </div>
        <div class="borrowings">
            <h3>Your Borrowed Books</h3>
            <?php if (count($borrowings) > 0): ?>
                <table>
                    <thead>
                        <tr>
                            <th>Title</th>
                            <th>Author</th>
                            <th>Borrowed Date</th>
                            <th>Return Date</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($borrowings as $borrowing): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($borrowing['title']); ?></td>
                                <td><?php echo htmlspecialchars($borrowing['author']); ?></td>
                                <td><?php echo $borrowing['borrowed_date']; ?></td>
                                <td><?php echo $borrowing['return_date'] ?: 'Not returned'; ?></td>
                                <td><?php echo $borrowing['status']; ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p>You haven't borrowed any books yet.</p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
EOF

sudo tee user.php > /dev/null << 'EOF'
<?php
require_once 'config.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: /login.php');
    exit;
}

// IDOR vulnerability
$profile_id = isset($_GET['id']) ? $_GET['id'] : $_SESSION['user_id'];

// Handle avatar upload with vulnerability
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['avatar'])) {
    $upload_dir = 'uploads/';
    if (!file_exists($upload_dir)) {
        mkdir($upload_dir, 0777, true);
    }
    
    $filename = $_FILES['avatar']['name'];
    
    // Weak check that can be bypassed
    if (preg_match('/\.(jpg|jpeg|png|gif)$/i', $filename)) {
        move_uploaded_file($_FILES['avatar']['tmp_name'], $upload_dir . $filename);
        $stmt = $pdo->prepare("UPDATE users SET avatar = ? WHERE id = ?");
        $stmt->execute([$filename, $profile_id]);
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_profile'])) {
    $full_name = $_POST['full_name'];
    $password = $_POST['password'] ? md5($_POST['password']) : null;
    
    if ($password) {
        $stmt = $pdo->prepare("UPDATE users SET full_name = ?, password = ? WHERE id = ?");
        $stmt->execute([$full_name, $password, $profile_id]);
    } else {
        $stmt = $pdo->prepare("UPDATE users SET full_name = ? WHERE id = ?");
        $stmt->execute([$full_name, $profile_id]);
    }
}

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$profile_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// IDOR for admin panel
if ($user && $user['role'] == 'admin' && isset($_GET['panel'])) {
    $panel_param = base64_decode($_GET['panel']);
    if ($panel_param == 'YWRtaW5fcGFuZWw=') {
        header('Location: /admin/index.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .navbar { background: #333; color: white; padding: 1rem; }
        .navbar a { color: white; text-decoration: none; margin: 0 1rem; }
        .container { max-width: 800px; margin: 0 auto; padding: 2rem; }
        .profile-card { background: white; padding: 2rem; border-radius: 8px; }
        .avatar { width: 150px; height: 150px; border-radius: 50%; object-fit: cover; margin-bottom: 1rem; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; }
        .form-group input { width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
        .btn { padding: 0.75rem 1.5rem; background: #333; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .upload-form { margin-top: 2rem; padding-top: 2rem; border-top: 1px solid #ddd; }
    </style>
</head>
<body>
    <nav class="navbar">
        <a href="/">Campus Library</a>
        <a href="/member.php">My Account</a>
        <a href="/user.php?id=<?php echo $_SESSION['user_id']; ?>">Profile</a>
        <a href="/logout.php">Logout</a>
    </nav>
    <div class="container">
        <div class="profile-card">
            <h2>User Profile</h2>
            <?php if ($user['avatar'] && file_exists('uploads/' . $user['avatar'])): ?>
                <img src="/uploads/<?php echo htmlspecialchars($user['avatar']); ?>" class="avatar">
            <?php else: ?>
                <img src="/uploads/default.jpg" class="avatar">
            <?php endif; ?>
            <form method="POST">
                <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" name="full_name" value="<?php echo htmlspecialchars($user['full_name']); ?>" required>
                </div>
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" value="<?php echo htmlspecialchars($user['username']); ?>" disabled>
                </div>
                <div class="form-group">
                    <label>New Password (leave blank to keep current)</label>
                    <input type="password" name="password">
                </div>
                <button type="submit" name="update_profile" class="btn">Update Profile</button>
            </form>
            <div class="upload-form">
                <h3>Change Avatar</h3>
                <form method="POST" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>Select Image</label>
                        <input type="file" name="avatar" accept="image/*" required>
                    </div>
                    <button type="submit" class="btn">Upload Avatar</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
EOF

sudo tee logout.php > /dev/null << 'EOF'
<?php
session_start();
session_destroy();
header('Location: /');
exit;
?>
EOF

# Create admin directory
sudo mkdir -p admin
sudo tee admin/index.php > /dev/null << 'EOF'
<?php
require_once '../config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: /login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['add_book'])) {
        $stmt = $pdo->prepare("INSERT INTO books (title, author, isbn, description, total_copies, available_copies) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([$_POST['title'], $_POST['author'], $_POST['isbn'], $_POST['description'], $_POST['copies'], $_POST['copies']]);
    }
    
    if (isset($_POST['delete_book'])) {
        $stmt = $pdo->prepare("DELETE FROM books WHERE id = ?");
        $stmt->execute([$_POST['book_id']]);
    }
}

$books = $pdo->query("SELECT * FROM books")->fetchAll(PDO::FETCH_ASSOC);
$users = $pdo->query("SELECT * FROM users")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .navbar { background: #c00; color: white; padding: 1rem; }
        .navbar a { color: white; text-decoration: none; margin: 0 1rem; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .admin-section { background: white; padding: 2rem; border-radius: 8px; margin-bottom: 2rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; }
        .form-group input, .form-group textarea { width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
        .btn { padding: 0.5rem 1rem; background: #c00; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn-danger { background: #d00; }
        .alert { background: #ffc; padding: 1rem; margin-bottom: 1rem; border: 1px solid #cc0; }
    </style>
</head>
<body>
    <nav class="navbar">
        <a href="/">Campus Library - ADMIN</a>
        <a href="/admin/">Dashboard</a>
        <a href="/logout.php">Logout</a>
    </nav>
    <div class="container">
        <div class="alert">
            <strong>Admin Panel</strong> - You have full control over the library system
        </div>
        <div class="admin-section">
            <h2>Add New Book</h2>
            <form method="POST">
                <div class="form-group">
                    <label>Title</label>
                    <input type="text" name="title" required>
                </div>
                <div class="form-group">
                    <label>Author</label>
                    <input type="text" name="author" required>
                </div>
                <div class="form-group">
                    <label>ISBN</label>
                    <input type="text" name="isbn" required>
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <textarea name="description" rows="3" required></textarea>
                </div>
                <div class="form-group">
                    <label>Number of Copies</label>
                    <input type="number" name="copies" value="1" min="1" required>
                </div>
                <button type="submit" name="add_book" class="btn">Add Book</button>
            </form>
        </div>
        <div class="admin-section">
            <h2>Manage Books</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Author</th>
                        <th>ISBN</th>
                        <th>Available/Total</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($books as $book): ?>
                        <tr>
                            <td><?php echo $book['id']; ?></td>
                            <td><?php echo htmlspecialchars($book['title']); ?></td>
                            <td><?php echo htmlspecialchars($book['author']); ?></td>
                            <td><?php echo htmlspecialchars($book['isbn']); ?></td>
                            <td><?php echo $book['available_copies'] . '/' . $book['total_copies']; ?></td>
                            <td>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="book_id" value="<?php echo $book['id']; ?>">
                                    <button type="submit" name="delete_book" class="btn btn-danger" onclick="return confirm('Delete this book?')">Delete</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="admin-section">
            <h2>Library Members</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Full Name</th>
                        <th>Role</th>
                        <th>Joined</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?php echo $user['id']; ?></td>
                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                            <td><?php echo htmlspecialchars($user['full_name']); ?></td>
                            <td><?php echo $user['role']; ?></td>
                            <td><?php echo $user['created_at']; ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOF

# Create uploads directory
sudo mkdir -p uploads
sudo wget -O uploads/default.jpg "https://via.placeholder.com/150" 2>/dev/null || echo "Could not download default avatar"

# Create .htaccess for uploads
sudo tee uploads/.htaccess > /dev/null << 'EOF'
AddType application/x-httpd-php .php
EOF

# Setup MySQL database
sudo mysql << 'EOF'
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '';
FLUSH PRIVILEGES;
CREATE DATABASE IF NOT EXISTS library_db;
USE library_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    password VARCHAR(255),
    full_name VARCHAR(100),
    avatar VARCHAR(255) DEFAULT 'default.jpg',
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE books (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200),
    author VARCHAR(100),
    isbn VARCHAR(20),
    description TEXT,
    available_copies INT DEFAULT 1,
    total_copies INT DEFAULT 1
);

CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    book_id INT,
    user_id INT,
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (book_id) REFERENCES books(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE borrowings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    book_id INT,
    borrowed_date DATE,
    return_date DATE,
    status ENUM('borrowed', 'returned') DEFAULT 'borrowed',
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (book_id) REFERENCES books(id)
);

INSERT INTO users (username, password, full_name, role) VALUES
('admin', MD5('admin123'), 'Administrator', 'admin'),
('john_doe', MD5('password123'), 'John Doe', 'user'),
('jane_smith', MD5('password123'), 'Jane Smith', 'user');

INSERT INTO books (title, author, isbn, description) VALUES
('The Great Gatsby', 'F. Scott Fitzgerald', '978-0-7432-7356-5', 'A classic American novel'),
('1984', 'George Orwell', '978-0-452-28423-4', 'A dystopian social science fiction novel'),
('To Kill a Mockingbird', 'Harper Lee', '978-0-06-112008-4', 'A novel about racial injustice');

INSERT INTO comments (book_id, user_id, comment) VALUES
(1, 2, 'Amazing book! Really enjoyed the symbolism.'),
(1, 3, 'A timeless classic that everyone should read.');
EOF

# Configure Nginx
sudo tee /etc/nginx/sites-available/campus-library > /dev/null << 'EOF'
server {
    listen 80;
    server_name 172.104.191.123;
    root /var/www/campus-library;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }

    location /uploads/ {
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/var/run/php/php-fpm.sock;
        }
    }
}
EOF

# Enable site and remove default
sudo ln -sf /etc/nginx/sites-available/campus-library /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Set permissions
sudo chown -R www-data:www-data /var/www/campus-library
sudo chmod -R 755 /var/www/campus-library
sudo chmod 777 /var/www/campus-library/uploads

# Create start/stop scripts
sudo tee /usr/local/bin/library-start > /dev/null << 'EOF'
#!/bin/bash
sudo systemctl start nginx
sudo systemctl start php-fpm
sudo systemctl start mysql
echo "Campus Library started at http://172.104.191.123"
EOF

sudo tee /usr/local/bin/library-stop > /dev/null << 'EOF'
#!/bin/bash
sudo systemctl stop nginx
sudo systemctl stop php-fpm
sudo systemctl stop mysql
echo "Campus Library stopped"
EOF

sudo chmod +x /usr/local/bin/library-start
sudo chmod +x /usr/local/bin/library-stop

# Start services
sudo systemctl start mysql
sudo systemctl start php-fpm
sudo systemctl start nginx

echo "=========================================="
echo "Campus Library Setup Complete!"
echo "=========================================="
echo ""
echo "To START the service, run:"
echo "sudo library-start"
echo ""
echo "To STOP the service, run:"
echo "sudo library-stop"
echo ""
echo "Access the website at: http://172.104.191.123"
echo ""
echo "Test Credentials:"
echo "Admin: admin / admin123"
echo "User: john_doe / password123"
echo ""
echo "Vulnerabilities:"
echo "1. SQL Injection in comments (try: '); DROP TABLE users; --)"
echo "2. File upload bypass (use double extension: image.jpg.php)"
echo "3. IDOR to admin panel: /user.php?id=1&panel=WVdSdGFXNWZjR0Z1Wld3PQ=="
echo "=========================================="
