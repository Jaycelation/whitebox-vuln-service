<?php
function load_user($user_id) {
    global $conn;
    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $user_id);
}
