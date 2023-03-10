<?php
session_start();
?>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
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
    echo "<a href='groups.php'>Groups</a>"; 
    echo "<a href='assignation.php'>USB Assignation</a> ";
  }
  ?>
  </div>
<div style="padding-left:16px">
  <h2>Keep your USB safe!</h2>
  <p>Tired of employees with bad cyber-security practices? Don't worry, we got you! Try us.</p>
</div>
<div style="padding-left:16px">
  <h2>How it works?</h2>
  <p>Just plug your USB into the machine and it will start the scan.</p>
</div>
</body>
</html>
