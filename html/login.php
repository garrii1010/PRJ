<!DOCTYPE html>
<?php
session_start();

$username = '';
$error = '';
if ($_POST) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $servername = "localhost";
    $usuname = "root";
    $pass = "contraseña";
    $dbname = "DBusb";
    
    // Create connection
    $conn = new mysqli($servername, $usuname, $pass, $dbname);
    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    } 
    $query = "SELECT id_usu FROM usuarios WHERE nombre = '$username' AND pass = '$password'";
    $result = mysqli_query($conn, $query);
    $row = mysqli_fetch_assoc($result);

    if (mysqli_num_rows($result) == 1) {
	    $_SESSION['user'] = $row['id_usu'];
        if ($_SESSION['user'] == 2) {
            header('Location: index.php');
            exit;
        }
        else {
            header('Location: index2.php');
            exit;
        }   
    } else {
        $error = 'Nombre de usuario o contraseña incorrectos.';
	echo "<script> alert('Usuario o contraseña incorrectos'); </script>";
    }

    mysqli_close($conn);
}
?>
<html>
<head>
    <title>Login Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f3f3f3;
        }
        #container {
            width: 350px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px #ccc;
        }
        .form-group {
            margin-bottom: 10px;
        }
        .form-group label {
            display: block;
            font-weight: bold;
            font-size: 16px;
            margin-bottom: 5px;
        }
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            box-sizing: border-box;
        }
        .btn {
            background-color: #337ab7;
            color: #fff;
            padding: 10px;
            border: 0;
            cursor: pointer;
            font-size: 16px;
        }
        body {
            margin: 0;
            font-family: Arial, Helvetica, Roboto;
        }

        .topnav {
            overflow: hidden;
            background-color: #333;
        }

        .topnav a {
            float: left;
            color: #f2f2f2;
            text-align: center;
            padding: 14px 16px;
            text-decoration: none;
            font-size: 17px;
        }

        .topnav a:hover {
            background-color: #ddd;
            color: black;
        }

        .topnav a.active {
            background-color: #04AA6D;
            color: white;
        }
        .nav2 {
  overflow: hidden;
  background-color: black;
}

.nav2 a {
  float: left;
  color: white;
  text-align: center;
  padding: 10px 16px;
  text-decoration: none;
  font-size: 17px;
}

.nav2 a:hover {
  background-color: #ddd;
  color: black;
}

.nav2 a.active {
  background-color: black;
  color: white;
}
    </style>
</head>
<body>
<h1>
  safeUSB
</h1>
<div class="topnav">
  <a href="index.php">About us</a>
  <a href="index2.php">Files</a>
  <a href="login.php">Log in</a>
  <a href="signin.php">Sign in</a>
</div>
<div class='nav2'>
<?php
if ($_SESSION['user'] == 2){
    echo "<a href='assignation.php'>USB Assignation</a> ";
    echo "<a href='groups.php'>Groups</a>"; 
	
}
?>
</div>
    <br>
    <br>
    <br>
    <div id="container">
        <h1>Log in</h1>
        <form method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" name="username" id="username" />
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" id="password" />
            </div>
            <div class="form-group">
                <input type="submit" value="Log in" class="btn-default" />
            </div>
        </form>
    </div>
</body>
</html>
