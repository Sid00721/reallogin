<?php
// Example PHP script

// Set content type to JSON
header("Content-Type: application/json");

// Simulated data (replace with your actual data or database query)
$data = [
    ["id" => 1, "name" => "John Doe", "email" => "john@example.com"],
    ["id" => 2, "name" => "Jane Smith", "email" => "jane@example.com"]
];

// Output data as JSON
echo json_encode($data);
?>
