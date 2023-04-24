<?php

include('config.php');
session_start();

if(isset($_POST['log'])){
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    if(empty($username) || empty($password)){
        $_SESSION['msg'] = 'brak nazwy użytkownika lub hasła';
        header('location: index.php');
        exit();
    }

    $haslo_hash = hash('sha512', $password);
    $sql = "SELECT username, password FROM users WHERE username = ? AND password = ?";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param('ss', $username, $haslo_hash);
    $stmt->execute();
    $wynik = $stmt->get_result();
    $znalezione = $wynik->num_rows;
    
    if($znalezione>0){
        $_SESSION['islog'] = TRUE;
        $_SESSION['username'] = $username;
        header('location: index.php');
        exit();
    }
    else{
        $_SESSION['msg'] = 'niepoprawna nazwa użytkownika lub hasło ';
        header('location: index.php');
        exit();
    }
}

$_SESSION['msg'] = '';

?>