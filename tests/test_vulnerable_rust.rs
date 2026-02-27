use std::process::Command;
use std::fs::File;
use std::env;

static mut COUNTER: i32 = 0;

fn process_user_input(user_data: &str) {
    // CWE-89: SQL injection via format!
    let query = format!("SELECT * FROM users WHERE id = {}", user_data);
    
    // CWE-78: Command injection
    let output = Command::new("sh")
        .arg("-c")
        .arg(user_data)
        .output()
        .expect("Failed to execute");
    
    // CWE-22: Path traversal
    let file = File::open(user_data).unwrap();
    
    // CWE-400: Panic on user input
    panic!("Error: {}", user_data);
    
    // CWE-754: unwrap on user input
    let num: i32 = user_data.parse().unwrap();
    
    // CWE-798: Hardcoded password
    let password = "supersecret123";
    
    // CWE-798: Hardcoded API key
    let api_key = "sk-1234567890abcdef";
    
    // CWE-758: Unsafe block
    unsafe {
        let ptr = 0x1234 as *const i32;
        let val = *ptr;
    }
    
    // CWE-327: Insecure hash
    let hash = md5::compute(user_data);
    
    // CWE-502: Deserialization without validation
    let data: User = serde_json::from_str(user_data).unwrap();
}

unsafe fn dangerous_function() {
    // Unsafe function
}
