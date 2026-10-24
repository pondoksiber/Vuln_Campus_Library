#!/bin/bash
# =============================================================================
#  Vulnerable Campus Library - Interactive Installer
# -----------------------------------------------------------------------------
#  FOR EDUCATIONAL / LAB USE ONLY.
#  This application is INTENTIONALLY VULNERABLE (SQL injection, unrestricted
#  file upload / RCE, IDOR). Deploy ONLY on an isolated VM you control and
#  never expose it to an untrusted network.
#
#  Unlike setup.sh, this script asks you for the deployment values (server
#  IP/domain, paths, database password, admin account) instead of hardcoding
#  them. The lab vulnerabilities themselves are preserved on purpose.
# =============================================================================

# Note: we deliberately do NOT use `set -e`. Some steps (optional downloads,
# firewall tweaks) are allowed to fail without aborting the whole install.

# ----- pretty output ---------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info() { echo -e "${GREEN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1" >&2; }
step() { echo -e "\n${BLUE}==>${NC} $1"; }

# ----- must be root ----------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    err "Please run as root:  sudo ./install.sh"
    exit 1
fi

# ----- defaults --------------------------------------------------------------
APP_DIR_DEFAULT="/var/www/campus-library"
DB_NAME_DEFAULT="library_db"
DB_USER_DEFAULT="root"
HTTP_PORT_DEFAULT="80"
ADMIN_USER_DEFAULT="admin"
ADMIN_PASS_DEFAULT="admin123"

# Best-effort detection of a sensible default server address.
DETECTED_LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
DETECTED_PUBLIC_IP="$(curl -s --max-time 5 ifconfig.me 2>/dev/null || true)"
DEFAULT_SERVER="${DETECTED_PUBLIC_IP:-${DETECTED_LOCAL_IP:-127.0.0.1}}"

# ----- banner ----------------------------------------------------------------
clear
echo "=============================================================="
echo "   Vulnerable Campus Library  -  Interactive Installer"
echo "=============================================================="
echo
warn "This installs an INTENTIONALLY VULNERABLE web app for training."
warn "Use it ONLY inside an isolated lab VM. Never on a production host."
echo

# ----- interactive prompts ---------------------------------------------------
read -rp "Server IP or domain [${DEFAULT_SERVER}]: " SERVER_NAME
SERVER_NAME="${SERVER_NAME:-$DEFAULT_SERVER}"

read -rp "Install directory [${APP_DIR_DEFAULT}]: " APP_DIR
APP_DIR="${APP_DIR:-$APP_DIR_DEFAULT}"

read -rp "HTTP port [${HTTP_PORT_DEFAULT}]: " HTTP_PORT
HTTP_PORT="${HTTP_PORT:-$HTTP_PORT_DEFAULT}"

read -rp "Database name [${DB_NAME_DEFAULT}]: " DB_NAME
DB_NAME="${DB_NAME:-$DB_NAME_DEFAULT}"

DB_USER="${DB_USER_DEFAULT}"
read -rsp "MySQL root password (blank = empty, matches original lab): " DB_PASS
echo

read -rp "App admin username [${ADMIN_USER_DEFAULT}]: " ADMIN_USER
ADMIN_USER="${ADMIN_USER:-$ADMIN_USER_DEFAULT}"
read -rp "App admin password [${ADMIN_PASS_DEFAULT}]: " ADMIN_PASS
ADMIN_PASS="${ADMIN_PASS:-$ADMIN_PASS_DEFAULT}"

# sed uses '|' as delimiter below, so reject values that would break it.
for v in "$SERVER_NAME" "$APP_DIR" "$DB_NAME" "$DB_USER" "$DB_PASS"; do
    case "$v" in
        *"|"*) err "Values must not contain the '|' character. Aborting."; exit 1 ;;
    esac
done

# ----- summary + confirm -----------------------------------------------------
echo
info "Configuration summary"
echo "    Server name/IP : ${SERVER_NAME}"
echo "    Install dir    : ${APP_DIR}"
echo "    HTTP port      : ${HTTP_PORT}"
echo "    Database       : ${DB_NAME} (user: ${DB_USER})"
echo "    DB password    : $( [ -n "$DB_PASS" ] && echo '(set)' || echo '(empty)')"
echo "    App admin      : ${ADMIN_USER} / ${ADMIN_PASS}"
echo
read -rp "Proceed with installation? [y/N]: " CONFIRM
case "$CONFIRM" in
    [yY]|[yY][eE][sS]) ;;
    *) warn "Aborted by user."; exit 0 ;;
esac

# =============================================================================
#  Installation
# =============================================================================
step "Installing packages (nginx, mysql-server, php-fpm, php-mysql, php-gd)"
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y nginx mysql-server php-fpm php-mysql php-gd curl wget || {
    err "Package installation failed."; exit 1; }

# Detect the real PHP-FPM service name and socket (version specific on Ubuntu).
PHP_FPM_SVC="$(systemctl list-unit-files 2>/dev/null | grep -oE 'php[0-9.]+-fpm\.service' | head -1 | sed 's/\.service$//')"
[ -z "$PHP_FPM_SVC" ] && PHP_FPM_SVC="php-fpm"
PHP_SOCK="$(ls /run/php/php*-fpm.sock 2>/dev/null | head -1)"
[ -z "$PHP_SOCK" ] && PHP_SOCK="/run/php/php-fpm.sock"
info "Using PHP-FPM service: ${PHP_FPM_SVC}"
info "Using PHP-FPM socket : ${PHP_SOCK}"

step "Creating application at ${APP_DIR}"
mkdir -p "$APP_DIR"
cd "$APP_DIR" || { err "Cannot enter ${APP_DIR}"; exit 1; }

# ----- config.php (values substituted) ---------------------------------------
cat > "$APP_DIR/config.php" << 'EOF'
<?php
$host = 'localhost';
$dbname = '__DB_NAME__';
$username = '__DB_USER__';
$password = '__DB_PASS__';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

session_start();
?>
EOF
sed -i "s|__DB_NAME__|${DB_NAME}|g; s|__DB_USER__|${DB_USER}|g; s|__DB_PASS__|${DB_PASS}|g" "$APP_DIR/config.php"

# ----- index.php (SQL injection in comments - intentional) -------------------
cat > "$APP_DIR/index.php" << 'EOF'
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

# ----- login.php -------------------------------------------------------------
cat > "$APP_DIR/login.php" << 'EOF'
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

# ----- member.php ------------------------------------------------------------
cat > "$APP_DIR/member.php" << 'EOF'
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

# ----- user.php (file upload bypass + IDOR - intentional) --------------------
cat > "$APP_DIR/user.php" << 'EOF'
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

# ----- logout.php ------------------------------------------------------------
cat > "$APP_DIR/logout.php" << 'EOF'
<?php
session_start();
session_destroy();
header('Location: /');
exit;
?>
EOF

# ----- admin/index.php -------------------------------------------------------
mkdir -p "$APP_DIR/admin"
cat > "$APP_DIR/admin/index.php" << 'EOF'
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

# ----- uploads dir + default avatar ------------------------------------------
step "Preparing uploads directory"
mkdir -p "$APP_DIR/uploads"
if ! wget -q -O "$APP_DIR/uploads/default.jpg" "https://placehold.co/150x150.png" 2>/dev/null; then
    warn "Could not download a default avatar; profiles will show a broken image until one is uploaded."
    : > "$APP_DIR/uploads/default.jpg"
fi

# ----- database --------------------------------------------------------------
step "Setting up MySQL database '${DB_NAME}'"
# Fresh MySQL on Ubuntu authenticates root via the unix socket, so this runs
# before any password is set. Values are substituted from the prompts above.
mysql << EOF
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${DB_PASS}';
FLUSH PRIVILEGES;
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
USE ${DB_NAME};

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    password VARCHAR(255),
    full_name VARCHAR(100),
    avatar VARCHAR(255) DEFAULT 'default.jpg',
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS books (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200),
    author VARCHAR(100),
    isbn VARCHAR(20),
    description TEXT,
    available_copies INT DEFAULT 1,
    total_copies INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    book_id INT,
    user_id INT,
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (book_id) REFERENCES books(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS borrowings (
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
('${ADMIN_USER}', MD5('${ADMIN_PASS}'), 'Administrator', 'admin'),
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
if [ $? -ne 0 ]; then
    warn "Database setup reported an error (it may already exist). Check manually if needed."
fi

# ----- nginx -----------------------------------------------------------------
step "Configuring nginx"
cat > /etc/nginx/sites-available/campus-library << 'EOF'
server {
    listen __HTTP_PORT__;
    server_name __SERVER_NAME__;
    root __APP_DIR__;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:__PHP_SOCK__;
    }

    # INTENTIONALLY VULNERABLE: allow PHP execution from the uploads directory
    # so an uploaded webshell (e.g. shell.php.jpg) can be run. Lab only.
    location /uploads/ {
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:__PHP_SOCK__;
        }
    }
}
EOF
sed -i "s|__HTTP_PORT__|${HTTP_PORT}|g; s|__SERVER_NAME__|${SERVER_NAME}|g; s|__APP_DIR__|${APP_DIR}|g; s|__PHP_SOCK__|${PHP_SOCK}|g" /etc/nginx/sites-available/campus-library

ln -sf /etc/nginx/sites-available/campus-library /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

if ! nginx -t; then
    err "nginx configuration test failed. Review /etc/nginx/sites-available/campus-library"
    exit 1
fi

# ----- permissions -----------------------------------------------------------
step "Setting permissions"
chown -R www-data:www-data "$APP_DIR"
chmod -R 755 "$APP_DIR"
chmod 777 "$APP_DIR/uploads"   # lab needs the web server to write uploads

# ----- start/stop helpers ----------------------------------------------------
step "Installing library-start / library-stop helpers"
cat > /usr/local/bin/library-start << EOF
#!/bin/bash
systemctl start nginx
systemctl start ${PHP_FPM_SVC}
systemctl start mysql
echo "Campus Library started at http://${SERVER_NAME}:${HTTP_PORT}"
EOF

cat > /usr/local/bin/library-stop << EOF
#!/bin/bash
systemctl stop nginx
systemctl stop ${PHP_FPM_SVC}
systemctl stop mysql
echo "Campus Library stopped"
EOF

chmod +x /usr/local/bin/library-start /usr/local/bin/library-stop

# ----- firewall (best effort) ------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
    ufw allow "${HTTP_PORT}/tcp" >/dev/null 2>&1 || true
fi

# ----- start services --------------------------------------------------------
step "Starting services"
systemctl enable mysql "${PHP_FPM_SVC}" nginx >/dev/null 2>&1 || true
systemctl restart mysql
systemctl restart "${PHP_FPM_SVC}"
systemctl restart nginx

# ----- done ------------------------------------------------------------------
BASE_URL="http://${SERVER_NAME}"
[ "${HTTP_PORT}" != "80" ] && BASE_URL="http://${SERVER_NAME}:${HTTP_PORT}"

echo
echo "=============================================================="
echo "   Campus Library Setup Complete!"
echo "=============================================================="
echo
echo "Start the service:  sudo library-start"
echo "Stop the service :  sudo library-stop"
echo
echo "Access the website at: ${BASE_URL}"
echo
echo "Test Credentials:"
echo "  Admin: ${ADMIN_USER} / ${ADMIN_PASS}"
echo "  User : john_doe / password123"
echo
echo "Intentional Vulnerabilities (lab practice):"
echo "  1. SQL Injection in comments  (try: '); DROP TABLE users; --)"
echo "  2. File upload bypass         (double extension: image.jpg.php)"
echo "  3. IDOR to admin panel        (/user.php?id=1&panel=WVdSdGFXNWZjR0Z1Wld3PQ==)"
echo "=============================================================="
