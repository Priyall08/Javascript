<?php



if (isset($_POST['name'], $_POST['phone'], $_POST['email'], $_POST['password'])) {
    $errorsArray = [];

    // Validation for name
    if (empty($_POST['name'])) {
        $errorsArray[] = 'Name is required';
    }

    // Validation for phone
    if (empty($_POST['phone'])) {
        $errorsArray[] = 'Phone is required';
    } elseif (!preg_match('/^\d{10}$/', $_POST['phone'])) {
        $errorsArray[] = 'Phone should only contain 10 digits';
    }

    // Validation for email
    if (empty($_POST['email'])) {
        $errorsArray[] = 'Email is required';
    } elseif (!filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL)) {
        $errorsArray[] = 'Invalid email format';
    } elseif (preg_match('/[A-Z]/', $_POST['email'])) {
        $errorsArray[] = 'Email should not contain capital letters';
    }

    // Validation for password
    if (empty($_POST['password'])) {
        $errorsArray[] = 'Password is required';
    } elseif (strlen($_POST['password']) < 8) {
        $errorsArray[] = 'Password should be at least 8 characters long';
    }

    if (count($errorsArray) > 0) {
        $errors['error_count'] = count($errorsArray);
        $errors['error_msg'] = $errorsArray;
        echo json_encode($errors);
        exit();
    }

   
    $servername = "localhost";
    $username = "admin";
    $password = "Admin@123";
    $database = "demo2";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=" . $database, $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e) {

        echo json_encode(['error_msg' => $e->getMessage(), 'error_count' => 1]);
        exit();
    }

    $name = htmlspecialchars(trim($_POST['name']));
    $email = htmlspecialchars(trim($_POST['email']));
    $phone = htmlspecialchars(trim($_POST['phone']));
    $password = trim($_POST['password']);

    $hashPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

    $sql = "INSERT INTO users (name, email, password, phone) VALUES (:name, :email, :password, :phone)";

    $prepare = $conn->prepare($sql);
    $params = [
        'name' => $name,
        'email' => $email,
        'password' => $hashPassword,
        'phone' => $phone,

    ];

    try {
        $prepare->execute($params);
        echo json_encode(['success_msg' => 'User has been registered']);
        exit();
    } catch (Exception $e) {
        echo json_encode(['error_msg' => $e->getMessage(), 'error_count' => 1]);
        exit();
    }
}

echo json_encode(['error_msg' => 'Access Denied', 'error_count' => 1]);
exit();
