
<?php
session_start();

/* DATABASE CONNECTION */
$dbHost = "localhost";
$dbUser = "technova_user";
$dbPass = "TechNova@2026";
$dbName = "company_db";

$conn = new mysqli($dbHost, $dbUser, $dbPass, $dbName);

if ($conn->connect_error) {
    die("Database Connection Failed: " . $conn->connect_error);
}

$conn->set_charset("utf8mb4");

$message = "";
$messageType = "error";

/* LOGOUT */
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit;
}

/* REGISTRATION */
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['register'])) {

    $name = trim($_POST['full_name']);
    $email = strtolower(trim($_POST['email']));
    $phone = trim($_POST['phone']);
    $department = trim($_POST['department']);
    $designation = trim($_POST['designation']);
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];

    if (
        $name === "" || $email === "" || $phone === "" ||
        $department === "" || $designation === "" || $password === ""
    ) {
        $message = "Please fill all fields.";
    } elseif (!preg_match("/^[a-zA-Z ]+$/", $name)) {
        $message = "Name should contain only letters and spaces.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Enter a valid email address.";
    } elseif (!preg_match("/^[0-9]{10}$/", $phone)) {
        $message = "Phone number must contain exactly 10 digits.";
    } elseif (strlen($password) < 8) {
        $message = "Password must contain at least 8 characters.";
    } elseif ($password !== $confirmPassword) {
        $message = "Passwords do not match.";
    } else {

        $check = $conn->prepare("SELECT id FROM users WHERE LOWER(email) = ?");
        $check->bind_param("s", $email);
        $check->execute();
        $check->store_result();

        if ($check->num_rows > 0) {
            $message = "Email address already registered.";
        } else {

            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            $role = "employee";

            $stmt = $conn->prepare(
                "INSERT INTO users
                (full_name, email, phone, department, designation, password, role)
                VALUES (?, ?, ?, ?, ?, ?, ?)"
            );

            $stmt->bind_param(
                "sssssss",
                $name,
                $email,
                $phone,
                $department,
                $designation,
                $hashedPassword,
                $role
            );

            if ($stmt->execute()) {
                $message = "Registration successful! Please login.";
                $messageType = "success";
            } else {
                $message = "Registration failed. Please try again.";
            }

            $stmt->close();
        }

        $check->close();
    }
}

/* LOGIN */
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['login'])) {

    $email = strtolower(trim($_POST['email']));
    $password = $_POST['password'];

    if ($email === "" || $password === "") {
        $message = "Please enter email address and password.";
    } else {

        $stmt = $conn->prepare(
            "SELECT id, full_name, email, phone, department,
             designation, password, role
             FROM users WHERE LOWER(email) = ? LIMIT 1"
        );

        $stmt->bind_param("s", $email);
        $stmt->execute();

        $result = $stmt->get_result();

        if ($result->num_rows === 1) {

            $user = $result->fetch_assoc();
            $storedPassword = $user['password'];

            // Support password_hash() and existing SHA-256 password
            $validPassword = password_verify($password, $storedPassword);

            if (!$validPassword && hash_equals(
                strtolower($storedPassword),
                hash("sha256", $password)
            )) {
                $validPassword = true;

                // Upgrade old SHA-256 password to secure password_hash()
                $newHash = password_hash($password, PASSWORD_DEFAULT);

                $update = $conn->prepare(
                    "UPDATE users SET password = ? WHERE id = ?"
                );
                $update->bind_param("si", $newHash, $user['id']);
                $update->execute();
                $update->close();
            }

            if ($validPassword) {

                session_regenerate_id(true);

                $_SESSION['user_id'] = $user['id'];
                $_SESSION['name'] = $user['full_name'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['role'] = $user['role'];

                header("Location: index.php?page=dashboard");
                exit;

            } else {
                $message = "Incorrect password. Please try again.";
            }

        } else {
            $message = "Email address not registered.";
        }

        $stmt->close();
    }
}

/* PAGE */
$page = $_GET['page'] ?? 'home';

if ($page === 'dashboard' && !isset($_SESSION['user_id'])) {
    header("Location: index.php?page=login");
    exit;
}

if (!in_array($page, ['home', 'register', 'login', 'dashboard'])) {
    $page = 'home';
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TechNova Solutions</title>

<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: Arial, sans-serif;
}

body {
    background: #f3f6fb;
    color: #243047;
}

header {
    background: #101d38;
    color: white;
    padding: 20px 7%;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 15px;
}

.logo {
    font-size: 25px;
    font-weight: bold;
}

.logo span {
    color: #38bdf8;
}

nav {
    display: flex;
    gap: 22px;
    flex-wrap: wrap;
}

nav a {
    color: white;
    text-decoration: none;
    font-size: 15px;
}

nav a:hover {
    color: #38bdf8;
}

.hero {
    min-height: 440px;
    padding: 100px 8%;
    background: linear-gradient(120deg, #10203f, #176a9c);
    color: white;
    display: flex;
    align-items: center;
}

.hero-content {
    max-width: 700px;
}

.hero h1 {
    font-size: 46px;
    margin-bottom: 20px;
}

.hero p {
    font-size: 18px;
    line-height: 1.7;
    margin-bottom: 28px;
}

.btn {
    display: inline-block;
    background: #0ea5e9;
    color: white;
    text-decoration: none;
    border: none;
    padding: 13px 23px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 15px;
    margin: 5px;
}

.btn:hover {
    background: #0284c7;
}

.btn-secondary {
    background: #263b5e;
}

.section {
    padding: 65px 8%;
    text-align: center;
}

.section h2 {
    font-size: 30px;
    margin-bottom: 15px;
}

.section-intro {
    color: #64748b;
    margin-bottom: 30px;
    line-height: 1.6;
}

.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 22px;
    margin-top: 30px;
}

.card {
    background: white;
    padding: 28px;
    border-radius: 12px;
    box-shadow: 0 5px 20px rgba(0,0,0,0.07);
    text-align: left;
}

.card h3 {
    color: #12618e;
    margin-bottom: 12px;
}

.card p {
    color: #64748b;
    line-height: 1.6;
}

.form-container {
    max-width: 520px;
    margin: 55px auto;
    padding: 35px;
    background: white;
    border-radius: 12px;
    box-shadow: 0 5px 25px rgba(0,0,0,0.08);
}

.form-container h2 {
    text-align: center;
    margin-bottom: 25px;
    color: #10203f;
}

.form-group {
    margin-bottom: 16px;
}

.form-group label {
    display: block;
    margin-bottom: 7px;
    font-weight: bold;
    font-size: 14px;
}

.form-group input,
.form-group select {
    width: 100%;
    padding: 12px;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    outline: none;
    font-size: 15px;
}

.form-group input:focus,
.form-group select:focus {
    border-color: #0ea5e9;
}

.form-container button {
    width: 100%;
    margin: 10px 0;
}

.message {
    max-width: 520px;
    margin: 20px auto 0;
    padding: 13px;
    border-radius: 6px;
    text-align: center;
    background: #fee2e2;
    color: #991b1b;
}

.message.success {
    background: #dcfce7;
    color: #166534;
}

.dashboard {
    padding: 45px 7%;
}

.dashboard h1 {
    margin-bottom: 12px;
}

.table-container {
    overflow-x: auto;
    margin-top: 25px;
    background: white;
    border-radius: 10px;
    padding: 15px;
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 750px;
}

th, td {
    padding: 13px;
    text-align: left;
    border-bottom: 1px solid #e2e8f0;
}

th {
    background: #10203f;
    color: white;
}

tr:hover {
    background: #f1f5f9;
}

.profile {
    background: white;
    margin-top: 25px;
    padding: 25px;
    border-radius: 10px;
    line-height: 2;
}

footer {
    background: #101d38;
    color: white;
    text-align: center;
    padding: 25px;
    margin-top: 50px;
}

@media(max-width: 650px) {
    header {
        flex-direction: column;
    }

    .hero h1 {
        font-size: 34px;
    }

    .hero {
        padding: 70px 7%;
    }

    .form-container {
        margin: 30px 15px;
        padding: 25px;
    }
}
</style>
</head>

<body>

<header>
    <div class="logo">TechNova <span>Solutions</span></div>

    <nav>
        <a href="index.php">Home</a>

        <?php if (!isset($_SESSION['user_id'])): ?>
            <a href="index.php?page=register">Register</a>
            <a href="index.php?page=login">Login</a>
        <?php else: ?>
            <a href="index.php?page=dashboard">Dashboard</a>
            <a href="index.php?logout=1">Logout</a>
        <?php endif; ?>
    </nav>
</header>

<?php if ($message !== ""): ?>
    <div class="message <?php echo $messageType === 'success' ? 'success' : ''; ?>">
        <?php echo htmlspecialchars($message); ?>
    </div>
<?php endif; ?>


<?php if ($page === 'home'): ?>

<section class="hero">
    <div class="hero-content">
        <h1>Welcome to TechNova Solutions</h1>

        <p>
            Building innovative digital solutions through technology,
            teamwork and creativity. We provide a professional environment
            where employees can grow and achieve success.
        </p>

        <?php if (!isset($_SESSION['user_id'])): ?>
            <a class="btn" href="index.php?page=register">Join Our Team</a>
            <a class="btn btn-secondary" href="index.php?page=login">Company Login</a>
        <?php else: ?>
            <a class="btn" href="index.php?page=dashboard">Go to Dashboard</a>
        <?php endif; ?>
    </div>
</section>

<section class="section">
    <h2>About Our Company</h2>
    <p class="section-intro">
        TechNova Solutions is committed to providing quality technology
        services and creating opportunities for professional development.
    </p>

    <div class="cards">
        <div class="card">
            <h3>Our Mission</h3>
            <p>To deliver innovative and reliable technology solutions.</p>
        </div>

        <div class="card">
            <h3>Our Vision</h3>
            <p>To become a trusted company through excellence and innovation.</p>
        </div>

        <div class="card">
            <h3>Our Team</h3>
            <p>We believe in teamwork, creativity and professional growth.</p>
        </div>
    </div>
</section>

<?php elseif ($page === 'register'): ?>

<div class="form-container">
    <h2>Employee Registration</h2>

    <form method="POST" onsubmit="return validateRegistration();">

        <div class="form-group">
            <label>Full Name</label>
            <input type="text" name="full_name" required>
        </div>

        <div class="form-group">
            <label>Email Address</label>
            <input type="email" name="email" required>
        </div>

        <div class="form-group">
            <label>Phone Number</label>
            <input type="text" name="phone" maxlength="10"
                   pattern="[0-9]{10}" required>
        </div>

        <div class="form-group">
            <label>Department</label>
            <select name="department" required>
                <option value="">Select Department</option>
                <option>IT</option>
                <option>Human Resources</option>
                <option>Finance</option>
                <option>Marketing</option>
                <option>Sales</option>
                <option>Administration</option>
            </select>
        </div>

        <div class="form-group">
            <label>Designation</label>
            <input type="text" name="designation" required>
        </div>

        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password"
                   minlength="8" required>
        </div>

        <div class="form-group">
            <label>Confirm Password</label>
            <input type="password" name="confirm_password"
                   minlength="8" required>
        </div>

        <button class="btn" type="submit" name="register">
            Register
        </button>
    </form>

    <p style="text-align:center;">
        Already registered?
        <a href="index.php?page=login">Login here</a>
    </p>
</div>

<?php elseif ($page === 'login'): ?>

<div class="form-container">
    <h2>Company Login</h2>

    <form method="POST">
        <div class="form-group">
            <label>Email Address</label>
            <input type="email" name="email"
                   placeholder="Enter your email address" required>
        </div>

        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password"
                   placeholder="Enter your password" required>
        </div>

        <button class="btn" type="submit" name="login">
            Login
        </button>
    </form>

    <p style="text-align:center;">
        New employee?
        <a href="index.php?page=register">Create an account</a>
    </p>
</div>

<?php elseif ($page === 'dashboard'): ?>

<?php
$role = $_SESSION['role'];

if ($role === 'admin') {

    $employees = $conn->query(
        "SELECT id, full_name, email, phone, department,
         designation, created_at
         FROM users WHERE role = 'employee' ORDER BY id DESC"
    );

} else {

    $admins = $conn->query(
        "SELECT id, full_name, email, phone, department,
         designation
         FROM users WHERE role = 'admin' ORDER BY id ASC"
    );
}
?>

<section class="dashboard">

    <h1>
        <?php echo $role === 'admin' ? 'Admin Dashboard' : 'Employee Dashboard'; ?>
    </h1>

    <p>Welcome, <strong>
        <?php echo htmlspecialchars($_SESSION['name']); ?>
    </strong></p>

    <div class="profile">
        <h3>My Account Details</h3>
        <p><strong>Name:</strong>
            <?php echo htmlspecialchars($_SESSION['name']); ?></p>
        <p><strong>Email:</strong>
            <?php echo htmlspecialchars($_SESSION['email']); ?></p>
        <p><strong>Role:</strong>
            <?php echo htmlspecialchars(ucfirst($role)); ?></p>
    </div>

    <?php if ($role === 'admin'): ?>

        <h2 style="margin-top:35px;">All Employee Details</h2>

        <div class="table-container">
            <table>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Phone</th>
                    <th>Department</th>
                    <th>Designation</th>
                    <th>Joined Date</th>
                </tr>

                <?php if ($employees && $employees->num_rows > 0): ?>
                    <?php while ($employee = $employees->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($employee['id']); ?></td>
                            <td><?php echo htmlspecialchars($employee['full_name']); ?></td>
                            <td><?php echo htmlspecialchars($employee['email']); ?></td>
                            <td><?php echo htmlspecialchars($employee['phone']); ?></td>
                            <td><?php echo htmlspecialchars($employee['department']); ?></td>
                            <td><?php echo htmlspecialchars($employee['designation']); ?></td>
                            <td><?php echo htmlspecialchars($employee['created_at']); ?></td>
                        </tr>
                    <?php endwhile; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="7">No employees registered yet.</td>
                    </tr>
                <?php endif; ?>
            </table>
        </div>

    <?php else: ?>

        <h2 style="margin-top:35px;">Admin Details</h2>

        <div class="table-container">
            <table>
                <tr>
                    <th>ID</th>
                    <th>Admin Name</th>
                    <th>Email</th>
                    <th>Phone</th>
                    <th>Department</th>
                    <th>Designation</th>
                </tr>

                <?php if ($admins && $admins->num_rows > 0): ?>
                    <?php while ($admin = $admins->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($admin['id']); ?></td>
                            <td><?php echo htmlspecialchars($admin['full_name']); ?></td>
                            <td><?php echo htmlspecialchars($admin['email']); ?></td>
                            <td><?php echo htmlspecialchars($admin['phone']); ?></td>
                            <td><?php echo htmlspecialchars($admin['department']); ?></td>
                            <td><?php echo htmlspecialchars($admin['designation']); ?></td>
                        </tr>
                    <?php endwhile; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="6">No admin details found.</td>
                    </tr>
                <?php endif; ?>
            </table>
        </div>

    <?php endif; ?>

    <br>
    <a class="btn" href="index.php?logout=1">Logout</a>

</section>

<?php endif; ?>

<footer>
    <p>&copy; 2026 TechNova Solutions. All Rights Reserved.</p>
</footer>

<script>
function validateRegistration() {
    const password = document.querySelector(
        'input[name="password"]'
    ).value;

    const confirmPassword = document.querySelector(
        'input[name="confirm_password"]'
    ).value;

    if (password !== confirmPassword) {
        alert("Passwords do not match!");
        return false;
    }

    if (password.length < 8) {
        alert("Password must contain at least 8 characters.");
        return false;
    }

    return true;
}
</script>

</body>
</html>
