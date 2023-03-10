<?php
session_start();

if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
?>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
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
    <?php
    $servername = "localhost";
    $username = "root";
    $password = "contraseña";
    $dbname = "DBusb";
    
    $usuario = $_SESSION['user'];
    // Create connection
    $conn = new mysqli($servername, $username, $password, $dbname);
    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    } 
    $sql = "SELECT ID, nombre, direccion, MD5 FROM archivos WHERE usb IN (SELECT id_usb FROM usb WHERE propietario = (SELECT id_usu FROM usuarios WHERE id_usu = '$usuario')) OR usb IN (SELECT id_usb FROM usb WHERE grupo = (SELECT id_gr FROM ubic WHERE id_usu = '$usuario'))";
    $result = $conn->query($sql);
    
    if ($result->num_rows > 0) {
        echo "<table><tr><th>Name</th><th>Download link</th></tr>";
        // output data of each row
        while($row = $result->fetch_assoc()) {
            echo "<tr><td>".$row["nombre"]."</td><td><a href=".$row["direccion"]." download>Download</td></tr>";
        }
        echo "</table>";
    } else {
        echo "0 results";
    }
    $conn->close();
    ?>
</body>
</html>
